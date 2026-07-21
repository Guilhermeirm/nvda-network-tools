# -*- coding: utf-8 -*-
# Utilitarios de baixo nivel: execucao de comandos do sistema, chamadas
# HTTP, disparo de threads em segundo plano e pequenas funcoes de
# formatacao. Nao depende de wx/gui/ui do NVDA - so biblioteca padrao -
# entao pode ser testado isoladamente sem o NVDA rodando.

import threading
import subprocess
import ctypes
import ctypes.wintypes
import socket
import struct
import urllib.request

# A documentacao oficial da NVDA e explicita: initTranslation() deve ser
# chamado "no topo de CADA modulo Python" do addon, nao uma vez so no
# arquivo principal (globalPlugins/networkTools.py) - cada modulo
# precisa da propria chamada pra ter _() de verdade. Uma tentativa
# anterior de resolver isso capturando uma copia do builtin (_ = _) se
# provou incorreta na pratica (confirmado ao vivo pelo usuario, num
# problema parecido no painel de Configuracoes) - initTranslation() e o
# jeito certo e documentado.
try:
	import addonHandler
	addonHandler.initTranslation()
except Exception:
	# Cobre teste isolado deste modulo fora da NVDA - addonHandler nao
	# existe ou nao acha o addon a partir daqui.
	def _(texto):
		return texto


def is_admin():
	try:
		return bool(ctypes.windll.shell32.IsUserAnAdmin())
	except Exception:
		return False


def wait_for_network_change():
	"""Bloqueia a thread chamadora ate o Windows reportar uma mudanca de
	endereco de rede (adaptador conectado/desconectado, IP mudou, trocou
	de rede Wi-Fi etc.) - via NotifyAddrChange() da iphlpapi.dll, a MESMA
	API que o proprio Windows usa internamente pra isso (nada de
	PowerShell/.NET aqui - e uma chamada nativa direta, sem custo de
	inicializacao nenhum).

	Chamada com Handle e Overlapped como NULL, a funcao BLOQUEIA a
	thread (sem gastar CPU, sem sondagem em loop) ate a proxima mudanca
	de verdade acontecer - e o proprio kernel do Windows quem avisa, na
	hora, em vez do addon ficar perguntando de tempos em tempos "mudou
	alguma coisa?".

	Devolve True quando uma mudanca de rede foi detectada; False se a
	chamada falhar por algum motivo (ambiente sem a DLL, por exemplo -
	nao deveria acontecer em Windows normal, mas evita derrubar a thread
	se acontecer; quem chama deve tratar False como "essa forma de
	deteccao nao esta disponivel, use so a sondagem periodica de
	reserva")."""
	try:
		ret = ctypes.windll.iphlpapi.NotifyAddrChange(None, None)
		return ret == 0
	except Exception:
		return False


# --- Ping ICMP nativo (sem spawnar processo) ---
#
# ping.exe ja e rapido de abrir (nativo do Windows, nao precisa de
# runtime nenhum) - mas AINDA ASSIM tem o custo de CreateProcess a cada
# chamada, que pesa quando o Monitor de Conexao chama isso a cada poucos
# segundos, indefinidamente. IcmpSendEcho (iphlpapi.dll) faz o mesmo
# ping ICMP como uma chamada de FUNCAO dentro do proprio processo do
# NVDA - sem processo novo nenhum, ordens de magnitude mais rapido que
# CreateProcess. PowerShell NAO resolveria isso: o custo de inicializar
# o runtime .NET a cada chamada (5-10s, ver get_ip_config() acima) e
# muito maior que o de abrir o ping.exe nativo que estamos tentando
# evitar - trocaria um problema pequeno por um bem maior.
#
# So funciona com IPv4 (socket.inet_aton so aceita esse formato) - o
# gateway de uma rede domestica/corporativa e praticamente sempre IPv4,
# entao isso cobre o caso de uso real do Monitor sem complicar com IPv6.

class _IpOptionInformation(ctypes.Structure):
	_fields_ = [
		("Ttl", ctypes.c_ubyte),
		("Tos", ctypes.c_ubyte),
		("Flags", ctypes.c_ubyte),
		("OptionsSize", ctypes.c_ubyte),
		("OptionsData", ctypes.c_void_p),
	]


class _IcmpEchoReply(ctypes.Structure):
	_fields_ = [
		("Address", ctypes.c_ulong),
		("Status", ctypes.c_ulong),
		("RoundTripTime", ctypes.c_ulong),
		("DataSize", ctypes.c_ushort),
		("Reserved", ctypes.c_ushort),
		("Data", ctypes.c_void_p),
		("Options", _IpOptionInformation),
	]


_icmp_handle = None
_icmp_unavailable = False

# CRITICO: sem declarar restype/argtypes explicitos, o ctypes assume por
# padrao que toda funcao devolve um inteiro de 32 bits (c_int) - mas
# IcmpCreateFile devolve um HANDLE, que e do tamanho de um PONTEIRO
# (64 bits num processo 64-bit, e o NVDA moderno roda como 64-bit). Sem
# essa declaracao, o valor do handle sai TRUNCADO/CORROMPIDO na volta da
# chamada, e todo IcmpSendEcho subsequente falha silenciosamente (handle
# invalido) - sem erro nenhum visivel, so "sem resposta" o tempo todo,
# mesmo pingando um roteador que esta obviamente de pe. Erro classico de
# ctypes em Windows 64-bit, facil de nao perceber porque nao da excecao
# nenhuma, so devolve dado errado.
#
# Isolado num try/except a parte (nao dentro de icmp_available()) porque
# isto roda na IMPORTACAO do modulo - em qualquer sistema que nao seja
# Windows, ctypes.windll nem existe (AttributeError na hora), e o modulo
# inteiro deixaria de importar. icmp_available()/icmp_ping() abaixo so
# usam essas funcoes se elas existirem de verdade.
try:
	_IcmpCreateFile = ctypes.windll.iphlpapi.IcmpCreateFile
	_IcmpCreateFile.restype = ctypes.wintypes.HANDLE
	_IcmpCreateFile.argtypes = []

	_IcmpSendEcho = ctypes.windll.iphlpapi.IcmpSendEcho
	_IcmpSendEcho.restype = ctypes.wintypes.DWORD
	_IcmpSendEcho.argtypes = [
		ctypes.wintypes.HANDLE,   # IcmpHandle
		ctypes.wintypes.ULONG,    # DestinationAddress (IPAddr)
		ctypes.c_void_p,          # RequestData
		ctypes.wintypes.WORD,     # RequestSize
		ctypes.c_void_p,          # RequestOptions
		ctypes.c_void_p,          # ReplyBuffer
		ctypes.wintypes.DWORD,    # ReplySize
		ctypes.wintypes.DWORD,    # Timeout
	]
except (AttributeError, OSError):
	_IcmpCreateFile = None
	_IcmpSendEcho = None


def icmp_available():
	"""True se a API ICMP nativa (IcmpCreateFile/IcmpSendEcho) esta
	disponivel neste processo. Tenta criar o handle na primeira chamada
	e guarda o resultado (sucesso ou falha) para as chamadas seguintes -
	assim quem chama pode decidir ANTES se vai usar icmp_ping() ou cair
	direto pro ping.exe de sempre, sem precisar tentar e falhar toda
	vez."""
	global _icmp_handle, _icmp_unavailable
	if _icmp_unavailable:
		return False
	if _icmp_handle is not None:
		return True
	if _IcmpCreateFile is None:
		_icmp_unavailable = True
		return False
	try:
		handle = _IcmpCreateFile()
		# INVALID_HANDLE_VALUE e -1 reinterpretado como HANDLE (todos os
		# bits em 1) - com restype correto, o ctypes ja devolve isso como
		# um ponteiro nulo/invalido reconhecivel, entao basta checar
		# "nao e verdadeiro" (0/None) em vez de comparar magic numbers de
		# 32 bits que nao fariam sentido pra um HANDLE de 64 bits.
		if not handle:
			_icmp_unavailable = True
			return False
		_icmp_handle = handle
		return True
	except Exception:
		_icmp_unavailable = True
		return False


def icmp_ping(host, timeout_ms=1000):
	"""Ping ICMP unico contra um host IPv4, via IcmpSendEcho - sem
	spawnar processo nenhum (ver comentario do modulo acima). Reaproveita
	um unico handle ICMP entre chamadas (criado por icmp_available() na
	primeira vez, nunca fechado explicitamente - o Windows libera sozinho
	quando o processo do NVDA termina).

	Devolve a latencia em ms (int) se respondeu dentro do timeout, ou
	None se falhou por qualquer motivo (API indisponivel, host invalido/
	nao-IPv4, sem resposta, etc.) - quem chama trata None uniformemente
	como "sem resposta", sem precisar saber o motivo exato."""
	if not icmp_available():
		return None
	try:
		dest = struct.unpack("<L", socket.inet_aton(host))[0]
		request_data = b"NetworkToolsPing"
		reply_size = ctypes.sizeof(_IcmpEchoReply) + len(request_data) + 8
		reply_buffer = ctypes.create_string_buffer(reply_size)
		ret = _IcmpSendEcho(
			_icmp_handle, dest, request_data, len(request_data),
			None, reply_buffer, reply_size, timeout_ms)
		if ret == 0:
			return None
		reply = _IcmpEchoReply.from_buffer(reply_buffer)
		if reply.Status != 0:  # IP_SUCCESS == 0
			return None
		return int(reply.RoundTripTime)
	except Exception:
		return None


# --- Tabela ARP e ARP ativo nativos (sem subprocesso, sem scapy/Npcap) ---
#
# arp_table_native() le a tabela ARP direto do kernel via GetIpNetTable -
# substitui "arp -a" (subprocesso + parsing de texto) por uma chamada de
# funcao dentro do processo. send_arp() manda um pedido ARP ATIVO pra um
# IP especifico via SendARP - a mesma informacao que uma biblioteca como
# scapy daria, mas sem precisar de scapy nem do driver de captura de
# pacotes (Npcap/WinPcap) que o scapy normalmente exige no Windows para
# construir pacotes crus. Nenhuma das duas funcoes exige Administrador.


class _MibIpNetRow(ctypes.Structure):
	_fields_ = [
		("dwIndex", ctypes.c_ulong),
		("dwPhysAddrLen", ctypes.c_ulong),
		("bPhysAddr", ctypes.c_ubyte * 8),
		("dwAddr", ctypes.c_ulong),
		("dwType", ctypes.c_ulong),
	]


try:
	_GetIpNetTable = ctypes.windll.iphlpapi.GetIpNetTable
	_GetIpNetTable.restype = ctypes.wintypes.DWORD
	_GetIpNetTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.wintypes.ULONG), ctypes.wintypes.BOOL]

	_SendARP = ctypes.windll.iphlpapi.SendARP
	_SendARP.restype = ctypes.wintypes.DWORD
	_SendARP.argtypes = [
		ctypes.wintypes.ULONG, ctypes.wintypes.ULONG,
		ctypes.c_void_p, ctypes.POINTER(ctypes.wintypes.ULONG),
	]
except (AttributeError, OSError):
	_GetIpNetTable = None
	_SendARP = None


def arp_table_native():
	"""Le a tabela ARP local direto via GetIpNetTable (iphlpapi.dll) -
	sem spawnar "arp -a" como subprocesso nem fazer parsing de texto
	(que, apesar de ja ser locale-independente hoje, ainda paga o custo
	de abrir um processo). Devolve dict IP -> MAC ("aa:bb:cc:dd:ee:ff"),
	ou None se a API nao estiver disponivel nesse Windows - quem chama
	deve cair pro "arp -a" de sempre nesse caso."""
	if _GetIpNetTable is None:
		return None
	try:
		size = ctypes.wintypes.ULONG(0)
		ret = _GetIpNetTable(None, ctypes.byref(size), False)
		if ret not in (0, 122):  # 122 = ERROR_INSUFFICIENT_BUFFER, esperado aqui
			return None
		buf = ctypes.create_string_buffer(size.value)
		ret = _GetIpNetTable(buf, ctypes.byref(size), False)
		if ret != 0:
			return None
		# MIB_IPNETTABLE comeca com dwNumEntries (DWORD), seguido do
		# array de MIB_IPNETROW - le a contagem primeiro pra saber
		# quantas linhas existem antes de reinterpretar o resto do
		# buffer como o array de structs.
		num_entries = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong))[0]
		rows = (_MibIpNetRow * num_entries).from_buffer(buf, ctypes.sizeof(ctypes.c_ulong))
		tabela = {}
		for row in rows:
			if row.dwPhysAddrLen != 6:
				continue
			mac_bytes = bytes(row.bPhysAddr[:6])
			if mac_bytes == b"\x00\x00\x00\x00\x00\x00":
				continue
			ip = socket.inet_ntoa(struct.pack("<L", row.dwAddr))
			tabela[ip] = ":".join(f"{b:02x}" for b in mac_bytes)
		return tabela
	except Exception:
		return None


def send_arp(dest_ip, timeout=0.5):
	"""Manda um pedido ARP ATIVO pra um IPv4 especifico e devolve o MAC
	de resposta ("aa:bb:cc:dd:ee:ff") se o aparelho responder, ou None
	se nao responder/erro. Nativo via SendARP (iphlpapi.dll) - a mesma
	informacao que uma ferramenta tipo scapy daria, sem precisar dela
	nem do driver de captura de pacotes que ela normalmente exige no
	Windows. So funciona dentro da mesma sub-rede local (ARP nao
	atravessa roteador) - e exatamente o caso de uso da Varredura de
	Dispositivos, que ja so varre a rede local.

	Praticamente todo aparelho numa LAN PRECISA responder ARP pra
	conseguir se comunicar (e como o IP vira endereco fisico na camada
	2), entao isto encontra aparelhos que bloqueiam ICMP (ping) mas
	ainda assim estao conectados.

	IMPORTANTE sobre timeout: SendARP NAO tem nenhum parametro de tempo
	limite - quem decide quanto esperar por uma resposta e a resolucao
	ARP interna do Windows sozinha, e para um IP que nao existe isso
	pode levar bem mais que qualquer timeout razoavel (numa varredura de
	rede inteira, a maioria dos enderecos NAO tem aparelho, entao esse
	caso "sem resposta" e o que mais pesa no tempo total). Por isso a
	chamada de verdade roda numa thread separada, e so esperamos por ela
	ATE "timeout" segundos - se nao responder a tempo, desistimos e
	devolvemos None mesmo que a chamada nativa continue rodando sozinha
	em segundo plano (thread daemon - nao trava o encerramento do NVDA,
	so fica ali ate a resolucao ARP do Windows desistir por conta
	propria, sem que ninguem mais espere por ela)."""
	if _SendARP is None:
		return None
	resultado = {}
	def _worker():
		try:
			dest = struct.unpack("<L", socket.inet_aton(dest_ip))[0]
			mac_buf = (ctypes.c_ubyte * 6)()
			mac_len = ctypes.wintypes.ULONG(6)
			ret = _SendARP(dest, 0, mac_buf, ctypes.byref(mac_len))
			if ret != 0:  # NO_ERROR
				return
			mac_bytes = bytes(mac_buf)
			if mac_bytes == b"\x00\x00\x00\x00\x00\x00":
				return
			resultado["mac"] = ":".join(f"{b:02x}" for b in mac_bytes)
		except Exception:
			pass
	t = threading.Thread(target=_worker, daemon=True)
	t.start()
	t.join(timeout=timeout)
	return resultado.get("mac")


def _console_codepage():
	# Descobre a pagina de codigo OEM REAL que o Windows usa para a saida
	# de programas de console (netsh, ipconfig, getmac etc.) quando nao
	# ha console visivel (nosso caso, com CREATE_NO_WINDOW). E a mesma
	# API que os proprios programas de console consultam internamente.
	try:
		cp = ctypes.windll.kernel32.GetOEMCP()
		if cp:
			return f"cp{cp}"
	except Exception:
		pass
	return None


def decode_console_bytes(raw):
	# Alguns comandos (ex.: "netsh interface ip show config") devolvem
	# UTF-8 mesmo quando o console usa outra pagina de codigo (OEM);
	# outros (ex.: "ipconfig", "tracert") usam a pagina de codigo OEM do
	# sistema. "utf-8" em modo estrito e um bom teste: só terá sucesso se
	# os bytes realmente formarem UTF-8 valido (ao contrario de "cp850",
	# que quase nunca falha e por isso nao serve como teste). Por isso ele
	# vem primeiro, com a pagina de codigo OEM real (via GetOEMCP) logo
	# depois como reserva.
	if not raw:
		return ""
	encodings = ["utf-8"]
	real_cp = _console_codepage()
	if real_cp and real_cp not in encodings:
		encodings.append(real_cp)
	for enc in ("cp850", "cp1252", "latin-1"):
		if enc not in encodings:
			encodings.append(enc)
	for enc in encodings:
		try:
			return raw.decode(enc)
		except Exception:
			continue
	return raw.decode("utf-8", errors="replace")


def run(args, timeout=30):
	try:
		p = subprocess.run(
			args, capture_output=True, timeout=timeout,
			creationflags=subprocess.CREATE_NO_WINDOW,
		)
		raw = p.stdout or p.stderr
		return True, decode_console_bytes(raw)
	except subprocess.TimeoutExpired:
		# translators: erro ao expirar o tempo de um comando do sistema
		return False, _("Tempo esgotado.")
	except Exception as e:
		return False, str(e)


def run_rc(args, timeout=30):
	"""Como run(), mas devolve tambem o codigo de saida (returncode) do
	processo, em vez de so True/False. Usado onde precisamos confirmar se um
	comando teve sucesso de verdade de forma INDEPENDENTE DE IDIOMA: o netsh
	imprime mensagens de confirmacao traduzidas (ex.: "Ok." em ingles,
	"Aceptar." em espanhol), entao procurar essas palavras no texto de saida
	nao e confiavel. O codigo de saida do proprio processo (0 = sucesso) e
	o unico sinal que nao muda com o idioma do Windows.
	Devolve (returncode_ou_None, texto_de_saida). returncode e None se o
	comando nem chegou a rodar (timeout ou erro do proprio Python)."""
	try:
		p = subprocess.run(
			args, capture_output=True, timeout=timeout,
			creationflags=subprocess.CREATE_NO_WINDOW,
		)
		raw = p.stdout or p.stderr
		return p.returncode, decode_console_bytes(raw)
	except subprocess.TimeoutExpired:
		return None, _("Tempo esgotado.")
	except Exception as e:
		return None, str(e)


def run_bg(fn):
	"""Dispara fn() em uma thread daemon separada. Substitui o padrao
	repetido "threading.Thread(target=fn, daemon=True).start()" que
	aparecia em quase todo handler de menu - agora e uma linha so, e
	qualquer ajuste futuro no jeito de criar threads (nome, prioridade,
	tratamento de excecao) muda num lugar so."""
	threading.Thread(target=fn, daemon=True).start()


def run_async(args, cb, timeout=30):
	def _w():
		ok, out = run(args, timeout)
		cb(ok, out)
	run_bg(_w)


def http(url, timeout=10):
	"""Requisicao GET simples. Usado pelas funcoes que consultam servicos
	publicos de leitura (geolocalizacao de IP, teste de velocidade) - nada
	no complemento precisa mais de POST desde que o teste de porta externo
	(canyouseeme.org) foi substituido por um teste local."""
	try:
		req = urllib.request.Request(
			url, headers={"User-Agent": "Mozilla/5.0 NVDA-NetworkTools/9"}
		)
		with urllib.request.urlopen(req, timeout=timeout) as r:
			return True, r.read().decode("utf-8", errors="replace")
	except Exception as e:
		return False, str(e)


def http_async(url, cb, timeout=10):
	def _w():
		ok, body = http(url, timeout)
		cb(ok, body)
	run_bg(_w)


def fmt(*pairs):
	return "\n".join(f"{k}: {v}" for k, v in pairs if v)


def format_speed(bps):
	mbps = bps / 1_000_000
	if mbps >= 1000:
		gbps = mbps / 1000
		return f"{gbps:.0f} Gbps" if gbps == int(gbps) else f"{gbps:.1f} Gbps"
	return f"{int(round(mbps))} Mbps"
