# -*- coding: utf-8 -*-
# Coleta e interpretacao de informacoes de rede (netsh, ipconfig, wmi,
# sockets, etc). Este modulo e deliberadamente livre de qualquer
# dependencia de wx/gui/ui do NVDA: cada funcao aqui recebe entradas
# simples e devolve dados (str, dict, list, None) em vez de mostrar
# qualquer coisa na tela. Quem decide COMO apresentar o resultado ao
# usuario e a camada de cima (globalPlugins/networkTools.py). Essa
# separacao e o que torna essas funcoes testaveis sem precisar do NVDA
# rodando (ver tests/).

import re
import os
import csv
import io
import socket
import struct
import time
import random
import statistics
import threading
import urllib.request
import urllib.error
import concurrent.futures

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
	# Cobre teste isolado deste modulo fora da NVDA (como neste projeto
	# sempre fizemos) - addonHandler nao existe ou nao acha o addon a
	# partir daqui, entao "_" fica so como identidade, suficiente pra
	# nao quebrar o import nem os testes.
	def _(texto):
		return texto

from . import regexes as rx
from .sysutils import run, run_rc, format_speed, icmp_ping, icmp_available, arp_table_native

def speedtest_sizes():
	"""Presets de tamanho do Teste de Velocidade - fonte UNICA de
	verdade, usada tanto pelo menu principal (globalPlugins/
	networkTools.py) quanto pelo painel de Configuracoes
	(networkToolsLib/settingsPanel.py). Fica aqui (nao em nenhum dos
	dois) de proposito: settingsPanel.py nao pode importar de
	globalPlugins/networkTools.py (import circular, ja que e o
	globalPlugins que importa settingsPanel, nunca o contrario) - antes
	disso cada arquivo tinha sua PROPRIA copia da lista, e elas
	DESSINCRONIZARAM na pratica (o rotulo do preset "Grande" foi
	atualizado num lugar e esquecido no outro).

	E uma FUNCAO (nao uma lista pronta no nivel do modulo) de proposito:
	os rotulos usam _() (traducao), que so fica disponivel depois que o
	addon chama addonHandler.initTranslation() - se essa lista fosse
	construida na hora que o modulo e importado, netinfo.py deixaria de
	poder ser importado sozinho (fora do addon, por exemplo em teste
	isolado) sem quebrar com "_ nao definido". Chamando _() so aqui
	dentro, na hora que alguem PEDE a lista, isso nunca acontece.

	Devolve uma lista de tuplas (id, rotulo traduzido, bytes de
	download, bytes de upload).

	"large" roda em 4 conexoes PARALELAS (ver _speedtest em
	globalPlugins/networkTools.py) - cada uma baixa/envia o valor CHEIO
	abaixo (nao dividido entre elas), entao o volume real de dados e 4x
	o numero mostrado no rotulo (200 MB download / 80 MB upload). Um
	bloco pequeno por conexao terminava rapido demais pra sair do "slow
	start" do TCP mesmo rodando em paralelo - confirmado ao vivo numa
	conexao de 1 Gbps, onde o resultado ficava bem abaixo do que outros
	medidores (fast.com) mostravam. 100 MB por conexao ja foi testado e
	o endpoint do Cloudflare devolve 403 Forbidden (parece existir um
	teto de tamanho por pedido no lado deles) - 50 MB e um valor
	confirmado que funciona."""
	return [
		("small", _("Pequeno (mais rápido, menos preciso) - 5 MB download, 2 MB upload"),
			5_000_000, 2_000_000),
		("medium", _("Médio, padrão - 25 MB download, 5 MB upload"),
			25_000_000, 5_000_000),
		("large", _("Grande, mais preciso em conexões rápidas - 200 MB download, 80 MB upload (4 conexões paralelas)"),
			50_000_000, 20_000_000),
	]

# Tabela de servidores DNS publicos conhecidos, usada para identificar o
# provedor pelo IP configurado. Nao e uma lista exaustiva de todo servidor
# DNS que existe (isso seria impossivel) - cobre apenas os servicos
# publicos mais usados. Servidores que nao aparecem aqui (tipicamente o IP
# do proprio roteador ou o resolver do provedor de internet local) caem no
# fallback de DNS reverso em identify_dns_provider().
KNOWN_DNS_PROVIDERS = {
	"8.8.8.8": "Google Public DNS",
	"8.8.4.4": "Google Public DNS",
	"1.1.1.1": "Cloudflare",
	"1.0.0.1": "Cloudflare",
	"9.9.9.9": "Quad9",
	"149.112.112.112": "Quad9",
	"208.67.222.222": "OpenDNS",
	"208.67.220.220": "OpenDNS",
	"208.67.222.220": "OpenDNS",
	"208.67.220.222": "OpenDNS",
	"64.6.64.6": "Verisign",
	"64.6.65.6": "Verisign",
	"84.200.69.80": "DNS.WATCH",
	"84.200.70.40": "DNS.WATCH",
	"76.76.2.0": "Control D",
	"76.76.19.19": "Control D",
	"94.140.14.14": "AdGuard DNS",
	"94.140.15.15": "AdGuard DNS",
	"185.228.168.9": "CleanBrowsing",
	"185.228.169.9": "CleanBrowsing",
	"8.26.56.26": "Comodo Secure DNS",
	"8.20.247.20": "Comodo Secure DNS",
	"4.2.2.1": "Level3",
	"4.2.2.2": "Level3",
	"77.88.8.8": "Yandex DNS",
	"77.88.8.1": "Yandex DNS",
	"149.112.121.10": "CIRA Canadian Shield",
	"149.112.122.10": "CIRA Canadian Shield",
	# Enderecos IPv6 dos mesmos provedores acima (mesmo servico, familia de
	# endereco diferente) - sem isto, digitar a versao IPv6 de um DNS
	# publico conhecido seria identificado como "nao identificado".
	# So inclui aqui enderecos de alta confianca (documentados oficialmente
	# pelo proprio provedor); Verisign e AdGuard ficaram de fora porque nao
	# ha certeza suficiente sobre os enderecos IPv6 deles.
	"2001:4860:4860::8888": "Google Public DNS",
	"2001:4860:4860::8844": "Google Public DNS",
	"2606:4700:4700::1111": "Cloudflare",
	"2606:4700:4700::1001": "Cloudflare",
	"2620:fe::fe": "Quad9",
	"2620:fe::9": "Quad9",
	"2620:119:35::35": "OpenDNS",
	"2620:119:53::53": "OpenDNS",
}

# Lista SEMENTE para a Busca de Melhor DNS (find_best_dns abaixo) - todos
# os enderecos IPv4 de KNOWN_DNS_PROVIDERS acima (mais de vinte servidores
# publicos conhecidos), na ordem em que foram cadastrados. So IPv4 porque
# apply_dns() usa "netsh interface ip", que e especifico de IPv4 no
# Windows (IPv6 exigiria "netsh interface ipv6", um comando separado que
# o addon ainda nao aplica); testar e depois nao poder aplicar so
# confundiria o usuario.
#
# NAO e mais uma lista fixa usada direto pela busca - e so a SEMENTE que
# popula o arquivo gerenciavel (ver load_dns_list) na primeira vez que o
# addon roda, pra nao comecar vazio. Depois da primeira vez, o usuario
# gerencia essa lista inteira (adicionar, editar, remover QUALQUER
# entrada, incluindo as que vieram daqui) via "Gerenciar Servidores DNS",
# sem precisar de nenhuma atualizacao do addon pra isso.
DEFAULT_DNS_CANDIDATES = [ip for ip in KNOWN_DNS_PROVIDERS if ":" not in ip]

# HTTP (nao HTTPS) e proposital aqui: o plano gratuito da API ip-api.com nao
# oferece suporte a HTTPS (isso exige plano pago). E seguro porque so
# consultamos o proprio IP publico do usuario (nenhum dado sensivel e
# enviado), entao o uso de HTTP simples e uma decisao tecnica aceitavel,
# nao um descuido.
GEO_URL = "http://ip-api.com/json/{ip}?lang=pt-BR&fields=status,country,regionName,city,timezone,isp,org,as,query"


# Prefixos de MAC (OUI) conhecidos de adaptadores de virtualizacao. Existem
# porque o NOME da interface nem sempre denuncia que ela e virtual - um
# adaptador VirtualBox Host-Only, por exemplo, pode aparecer como "Ethernet
# 2" (nome generico do Windows), sem nada que bata com RX_VIRTUAL_IFACE.
# O prefixo de MAC e uma marca registrada do fabricante e nao muda com o
# nome que o usuario (ou o Windows) da ao adaptador.
_VIRTUAL_MAC_PREFIXES = (
	"0a0027",  # VirtualBox Host-Only Network (endereco administrado localmente)
	"080027",  # VirtualBox (adaptadores "bridged"/NAT, OUI registrado da Oracle/Sun)
	"005056",  # VMware
	"000c29",  # VMware
	"000569",  # VMware
	"00155d",  # Hyper-V (Virtual Switch)
)


def _all_macs():
	"""Le getmac.exe UMA vez so e devolve {nome_da_interface: mac_sem_separadores}.
	Existe para nao precisar chamar get_mac_address() (que roda getmac de
	novo) uma vez por adaptador na hora de reclassificar virtual/nao-virtual."""
	ok, out = run(["getmac", "/fo", "csv", "/v"], timeout=5)
	if not ok or not out.strip():
		return {}
	try:
		rows = list(csv.reader(io.StringIO(out)))
	except Exception:
		return {}
	result = {}
	for row in rows[1:]:
		if len(row) >= 3 and row[2].strip() and row[2].strip() != "N/A":
			result[row[0].strip()] = row[2].strip().replace("-", "").replace(":", "").lower()
	return result


def _reclassify_by_mac(non_virtual, virtual):
	"""Move para a lista 'virtual' qualquer adaptador de non_virtual cujo
	MAC bata com um fabricante de virtualizacao conhecido - mesmo que o
	NOME do adaptador nao denuncie isso (ex.: VirtualBox aparecendo como
	'Ethernet 2'). So faz a chamada extra (getmac) se houver mais de um
	adaptador para verificar, pra nao pagar o custo a toa no caso comum
	de uma unica interface ativa."""
	if len(non_virtual) <= 1:
		return non_virtual, virtual
	macs = _all_macs()
	if not macs:
		return non_virtual, virtual
	ainda_nao_virtual = []
	for parsed in non_virtual:
		mac = macs.get(parsed.get("iface"), "")
		if mac and any(mac.startswith(p) for p in _VIRTUAL_MAC_PREFIXES):
			virtual.append(parsed)
		else:
			ainda_nao_virtual.append(parsed)
	return ainda_nao_virtual, virtual


def _parse_ip_show_config_blocks(out):
	"""Le a saida completa de 'netsh interface ip show config' e devolve
	(nao_virtuais, virtuais): duas listas de dicts, uma por adaptador com
	IP valido. Extraida de get_ip_config() para ser reaproveitada tambem
	por all_ip_configs(), que precisa da lista inteira em vez de escolher
	um adaptador so."""
	blocks = re.split(r"\n(?=Configuration|Configuraci[oó]n|Konfiguration|Configurazione|Конфигурация|配置)", out)

	def _parse_block(block):
		iface_m = rx.RX_NETSH_IF.search(block)
		iface = iface_m.group(1).strip() if iface_m else None
		m_ip = rx.RX_NETSH_IP.search(block)
		if not m_ip:
			return None
		ip = m_ip.group(1)
		if ip.startswith("169.254.") or ip == "0.0.0.0":
			return None
		mask = (m := rx.RX_NETSH_MASK.search(block)) and m.group(1)
		gw   = (m := rx.RX_NETSH_GW.search(block))   and m.group(1)
		dns  = []
		m = rx.RX_NETSH_DNS.search(block)
		if m:
			dns.append(m.group(1))
			for extra in rx.RX_DNS2.findall(block[m.end():]):
				if extra not in dns:
					dns.append(extra)
		dhcp = None
		m = rx.RX_DHCP.search(block)
		if m:
			val = m.group(1).strip().strip(".").lower()
			dhcp = val in rx.DHCP_YES_WORDS
		return {"ipv4": ip, "mask": mask, "gateway": gw, "dns": dns, "iface": iface, "dhcp": dhcp}

	non_virtual = []
	virtual = []
	for block in blocks:
		parsed = _parse_block(block)
		if not parsed:
			continue
		i = parsed.get("iface")
		if i and rx.RX_VIRTUAL_IFACE.search(i):
			virtual.append(parsed)
		else:
			non_virtual.append(parsed)
	non_virtual, virtual = _reclassify_by_mac(non_virtual, virtual)
	return non_virtual, virtual


def get_ip_config(iface=None):
	# Usa "netsh interface ip show config" — resposta em ~100ms pois
	# netsh.exe ja esta carregado pelo Windows, ao contrario do PowerShell
	# que precisa inicializar o .NET (5-10s).
	# Os campos numericos (enderecos IP) sao os mesmos em qualquer idioma
	# do Windows; so os rotulos de texto mudam, e as regex acima cobrem
	# todos os idiomas suportados.
	# iface: quando informado (selecao manual do usuario), forca a busca
	# por essa interface especifica em vez de deixar a deteccao
	# automatica escolher - mesmo que essa interface nao seja a usada
	# para trafego de saida agora (ex.: o usuario quer configurar um
	# adaptador que esta conectado mas ocioso no momento).
	ok, out = run(["netsh", "interface", "ip", "show", "config"], timeout=5)
	if not ok or not out.strip():
		return None
	non_virtual, virtual = _parse_ip_show_config_blocks(out)

	# Interface pedida explicitamente (selecao manual do usuario) tem
	# prioridade absoluta - NUNCA cai no automatico quando isso acontece,
	# mesmo que a interface pedida nao tenha IP valido agora. Um bug real
	# ja aconteceu aqui antes: pedir "Ethernet" (sem IP configurado no
	# momento) caia silenciosamente no Wi-Fi (o automatico), fazendo a
	# tela de Status de IP mostrar dados do Wi-Fi mesmo com "Ethernet"
	# selecionado manualmente - misturando adaptadores diferentes sem
	# avisar. Cada adaptador tem que ser independente: se a interface
	# pedida nao tem IP valido, a resposta correta e None (quem chama
	# decide como avisar o usuario disso), nunca substituir por outra.
	if iface:
		for parsed in non_virtual + virtual:
			if parsed.get("iface") == iface:
				return parsed
		return None

	# Identifica a interface realmente usada para trafego de saida (a que
	# o Windows escolhe de fato quando ha mais de um adaptador com IP
	# configurado, ex.: Ethernet conectado porem ocioso + Wi-Fi ativo).
	real_ip = local_ip()
	if real_ip:
		for parsed in non_virtual + virtual:
			if parsed["ipv4"] == real_ip:
				return parsed

	# Reserva: nenhum bloco bateu com o IP de saida real (ou nao foi
	# possivel determina-lo). Antes de so pegar o primeiro da lista (que
	# nao segue ordem de prioridade de uso real nem sabe status de
	# conexao), tenta preferir um adaptador que o Windows ja reporta como
	# conectado agora - reduz a chance de escolher um adaptador ligado
	# mas sem saida real (ex.: Ethernet num switch sem internet).
	if non_virtual:
		connected_names = {i["name"] for i in list_interfaces() if i["connected"]}
		for parsed in non_virtual:
			if parsed.get("iface") in connected_names:
				return parsed
		return non_virtual[0]
	if virtual:
		return virtual[0]
	return None


def all_ip_configs():
	"""Como get_ip_config(), mas devolve TODOS os adaptadores com IP
	valido (fisicos primeiro, depois virtuais) em vez de escolher um so.
	Usado pela tela de Status de IP quando ha mais de uma interface ativa
	na maquina e nenhuma foi escolhida manualmente - nesse caso, mostrar
	todas em abas e mais util do que adivinhar qual interessa."""
	ok, out = run(["netsh", "interface", "ip", "show", "config"], timeout=5)
	if not ok or not out.strip():
		return []
	non_virtual, virtual = _parse_ip_show_config_blocks(out)
	return non_virtual + virtual


def active_block(out):
	parts = re.split(r"\n(?=[^\s\n].+:\s*\n)", out)
	# Primeira passada: ignora blocos de adaptadores virtuais/VPN/tunel
	for b in parts:
		if rx.RX_DISC.search(b) or rx.RX_VIRTUAL_IFACE.search(b.split("\n", 1)[0]):
			continue
		m = rx.RX_IPV4.search(b)
		if m and not m.group(1).startswith("169.254."):
			return b
	# Segunda passada (reserva): aceita qualquer bloco, mesmo virtual
	for b in parts:
		if rx.RX_DISC.search(b):
			continue
		m = rx.RX_IPV4.search(b)
		if m and not m.group(1).startswith("169.254."):
			return b
	return out


def parse_ipcfg(out):
	# Reserva de get_ip_config() (baseada em netsh) - usada so quando o
	# netsh nao devolve nada de aproveitavel. So reconhece rotulos em
	# espanhol, ingles e portugues.
	b = active_block(out)
	ipv4 = (m := rx.RX_IPV4.search(b)) and m.group(1)
	mask = (m := rx.RX_MASK.search(b)) and m.group(1)
	gw   = (m := rx.RX_GW.search(b))   and m.group(1)
	dns  = []
	m = rx.RX_DNS.search(b)
	if m:
		dns.append(m.group(1))
		for x in rx.RX_DNS2.findall(b[m.end():]):
			if x not in dns:
				dns.append(x)
	return {"ipv4": ipv4, "mask": mask, "gateway": gw, "dns": dns}


def public_ip_nslookup():
	# Metodo primario: pergunta ao proprio OpenDNS "qual IP esta me
	# consultando" via o dominio especial myip.opendns.com. E rapido e nao
	# depende de HTTP, mas so funciona se a consulta chegar de fato aos
	# servidores do OpenDNS sem ser interceptada no caminho.
	ok, out = run(["nslookup", "myip.opendns.com", "resolver1.opendns.com"], 10)
	if not ok:
		return None
	ips = rx.RX_NSLOOKUP.findall(out)
	for ip in ips:
		p = list(map(int, ip.split(".")))
		private = (p[0]==10 or (p[0]==172 and 16<=p[1]<=31)
			or (p[0]==192 and p[1]==168) or p[0]==127)
		if private:
			continue
		if ip in rx.OPENDNS_RESOLVER_IPS:
			# A rede esta interceptando/redirecionando DNS (ou o usuario
			# esta atras de CGNAT): a consulta nao chegou ao servico real
			# de deteccao, e o que respondeu foi o proprio resolver
			# OpenDNS "falando de si mesmo". Esse IP nao e o IP publico
			# do usuario - descarta e deixa o chamador cair para o metodo
			# HTTP, que e imune a esse tipo de interceptacao de DNS.
			continue
		return ip
	return None


def local_ip():
	# IP realmente em uso para trafego de saida (independe de idioma do
	# Windows). Usa TCP (SOCK_STREAM), nao UDP: um socket UDP "conectado"
	# nunca envia pacote nenhum - so consulta a tabela de rotas local e
	# devolve um endereco, mesmo que aquela rota nao leve a lugar nenhum
	# de verdade (por exemplo, um adaptador Ethernet ligado a um switch
	# sem saida para a internet, mas com uma metrica de rota melhor que a
	# do Wi-Fi que esta genuinamente conectado). TCP exige um handshake
	# de verdade: se a rota escolhida pelo Windows nao chega em lugar
	# nenhum, o connect() falha e caimos no fallback abaixo em vez de
	# reportar um adaptador errado como "o ativo".
	try:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.settimeout(2.5)
			s.connect(("8.8.8.8", 53))
			return s.getsockname()[0]
	except Exception:
		return None


def active_iface():
	# Tenta obter o nome da interface direto do get_ip_config (rapido,
	# sem chamada extra). Se nao vier, faz o cruzamento via netsh.
	d = get_ip_config()
	if d and d.get("iface"):
		return d["iface"]
	# Fallback: cruza o IP de saida com as interfaces listadas
	ip = local_ip()
	ok, out = run(["netsh", "interface", "ipv4", "show", "interfaces"])
	names = []
	if ok:
		for line in out.splitlines():
			m = rx.RX_IFACE_ROW.match(line)
			if m and not m.group(1).lower().startswith(("idx", "---")):
				names.append(m.group(1).strip())
	if ip and names:
		for name in names:
			ok2, out2 = run(["netsh", "interface", "ipv4", "show", "addresses", f"name={name}"])
			if ok2 and ip in out2:
				return name
	if ok:
		for line in out.splitlines():
			if rx.RX_IFACE.search(line):
				m = rx.RX_IFACE_ROW.match(line)
				if m:
					return m.group(1).strip()
	return names[0] if names else None


def list_interfaces():
	"""Lista todas as interfaces de rede que o Windows conhece agora (nao
	so a ativa), com o status de conexao de cada uma. Usado so pelo
	seletor manual de interface, pra popular a lista de escolha -
	active_iface() continua sendo a deteccao automatica de sempre.
	Adaptadores fantasmas/ocultos do Windows (WAN Miniport de VPN e
	afins, sempre nomeados com um asterisco no final) ficam de fora, ja
	que nunca sao uteis para selecionar manualmente."""
	ok, out = run(["netsh", "interface", "ipv4", "show", "interfaces"])
	if not ok:
		return []
	result = []
	for line in out.splitlines():
		m = rx.RX_IFACE_ROW.match(line)
		if not m:
			continue
		name = m.group(1).strip()
		if not name or name.lower().startswith(("idx", "---")):
			continue
		if rx.RX_HIDDEN_IFACE.search(name):
			continue
		result.append({"name": name, "connected": bool(rx.RX_IFACE.search(line))})
	return result


def wifi_interfaces(out):
	"""Divide a saida de 'netsh wlan show interfaces' em um bloco por
	adaptador Wi-Fi. Com um radio so (o caso comum), devolve uma lista de
	1 item; com mais de um radio Wi-Fi na maquina, cada adaptador vem
	separado - assim quem chama pode escolher o bloco certo (pela
	interface selecionada manualmente, ou o primeiro que estiver com uma
	rede conectada de verdade) em vez de misturar campos de adaptadores
	diferentes num resultado so."""
	blocks = re.split(r"\n\s*\n+", out.strip())
	result = []
	for block in blocks:
		m = rx.RX_WLAN_NAME.search(block)
		if not m:
			continue
		name = m.group(1).strip()
		ssid_m = rx.RX_SSID.search(block)
		result.append({
			"name": name,
			"ssid": ssid_m.group(1).strip() if ssid_m else None,
			"connected": bool(rx.RX_IFACE.search(block)),
			"block": block,
		})
	return result


def wifi_ssid_for_iface(iface_name):
	"""Consulta o SSID da rede Wi-Fi conectada num adaptador especifico
	(por nome) - usado pelo Monitor de Conexao pra identificar QUAL rede
	esta associando as estatisticas, ja que o mesmo adaptador Wi-Fi pode
	se conectar a redes diferentes ao longo do tempo (ver
	_resolve_network_identity em globalPlugins/networkTools.py).

	Devolve o SSID (str) ou None se o adaptador nao for Wi-Fi, nao
	estiver conectado a nenhuma rede agora, ou o SSID nao puder ser
	lido - nunca lanca excecao."""
	if not iface_name:
		return None
	try:
		ok, out = run(["netsh", "wlan", "show", "interfaces"], timeout=5)
		if not ok:
			return None
		for info in wifi_interfaces(out):
			if info["name"].strip().lower() == iface_name.strip().lower() and info["connected"]:
				return info["ssid"]
	except Exception:
		pass
	return None


def gateway_mac(gateway_ip):
	"""Descobre o MAC do gateway - usado pelo Monitor de Conexao como
	identificador de uma rede SEM Wi-Fi (Ethernet, adaptador virtual
	etc.), que nao tem SSID nenhum pra usar. O MAC do roteador e um
	identificador fisico estavel (nao muda so porque o IP do gateway
	mudou via DHCP, ao contrario do proprio IP).

	Devolve o MAC (str "XX:XX:XX:XX:XX:XX") ou None se o gateway nao
	for informado ou o MAC nao puder ser encontrado na tabela ARP."""
	if not gateway_ip:
		return None
	try:
		return arp_table().get(gateway_ip)
	except Exception:
		return None


def get_mac_address(iface):
	# getmac.exe e nativo e rapido (nao precisa do PowerShell). O texto do
	# cabecalho do CSV muda de idioma, mas lemos pela POSICAO da coluna
	# (1a = nome da conexao, 3a = endereco fisico), entao funciona em
	# qualquer idioma do Windows.
	ok, out = run(["getmac", "/fo", "csv", "/v"], timeout=5)
	if not ok or not out.strip():
		return None
	try:
		rows = list(csv.reader(io.StringIO(out)))
	except Exception:
		return None
	if len(rows) < 2:
		return None
	for row in rows[1:]:
		if len(row) >= 3 and row[0].strip().lower() == iface.strip().lower():
			mac = row[2].strip()
			if mac and mac != "N/A":
				return mac
	# Se nao achou por nome exato, devolve o primeiro MAC valido encontrado
	for row in rows[1:]:
		if len(row) >= 3 and row[2].strip() and row[2].strip() != "N/A":
			return row[2].strip()
	return None


def get_link_speed(iface):
	# Consulta o WMI para descobrir a velocidade do link do adaptador.
	#
	# Usa comtypes, NAO win32com/pythoncom (pywin32): o NVDA usa comtypes
	# para automacao COM e nem sempre traz pywin32 embutido, entao
	# comtypes e a biblioteca que de fato esta disponivel dentro do
	# processo do NVDA.
	try:
		import comtypes
		import comtypes.client as cc
	except ImportError:
		return None
	from .sysutils import format_speed

	try:
		comtypes.CoInitialize()
	except Exception:
		pass

	def _query(namespace, wql):
		try:
			locator = cc.CreateObject("WbemScripting.SWbemLocator")
			service = locator.ConnectServer(".", namespace)
			return list(service.ExecQuery(wql))
		except Exception:
			return []

	def _prop(item, name):
		# Le uma propriedade WMI de forma robusta. O acesso direto por
		# atributo (item.NetConnectionID) e o jeito mais comum de ler
		# propriedades COM Automation, mas com o despacho dinamico do
		# comtypes ele pode falhar mesmo quando a propriedade existe de
		# verdade. A colecao "Properties_" e a forma generica e
		# documentada de ler qualquer propriedade de um objeto WMI
		# (SWbemObject), e e mais robusta nesse cenario - por isso ela e
		# a nossa reserva aqui.
		try:
			return getattr(item, name)
		except Exception:
			try:
				return item.Properties_(name).Value
			except Exception:
				return None

	try:
		iface_low = iface.strip().lower()

		# 1a tentativa: MSFT_NetAdapter (namespace StandardCimv2). E a
		# mesma classe que o "Get-NetAdapter" do PowerShell usa por baixo
		# dos panos e e bem mais confiavel que a classe antiga abaixo.
		for item in _query(r"root\StandardCimv2", "SELECT Name, LinkSpeed FROM MSFT_NetAdapter"):
			name = _prop(item, "Name")
			speed = _prop(item, "LinkSpeed")
			if name and str(name).strip().lower() == iface_low and speed:
				try:
					bps = int(speed)
				except Exception:
					continue
				if bps > 0:
					return format_speed(bps)

		# Reserva: classe antiga Win32_NetworkAdapter (namespace cimv2
		# padrao). Em algumas maquinas e a unica disponivel, mas seu
		# campo "Speed" e conhecido por nem sempre retornar valor.
		#
		# NAO filtramos por "WHERE NetEnabled = True": esse campo pode
		# vir False/nulo para adaptadores que estao, na pratica, ativos
		# e conectados, o que excluiria da consulta um adaptador real.
		# Em vez disso, aceitamos qualquer adaptador com NetConnectionID
		# preenchido e deixamos a checagem "speed and bps > 0" logo
		# abaixo garantir que so aceitamos um valor valido.
		for item in _query(
			r"root\cimv2",
			"SELECT NetConnectionID, Speed FROM Win32_NetworkAdapter "
			"WHERE NetConnectionID IS NOT NULL"):
			name = _prop(item, "NetConnectionID")
			speed = _prop(item, "Speed")
			if name and str(name).strip().lower() == iface_low and speed:
				try:
					bps = int(speed)
				except Exception:
					continue
				if bps > 0:
					return format_speed(bps)

		return None
	finally:
		try:
			comtypes.CoUninitialize()
		except Exception:
			pass


def _ipv6_addr_list(iface):
	"""Le 'netsh interface ipv6 show address' e devolve TODOS os enderecos
	IPv6 da interface (globais e link-local), sem escolher qual devolver -
	quem decide isso e get_ipv6()/ipv6_addresses(). Extraida como funcao
	separada para nao duplicar o parsing entre as duas."""
	ok, out = run(["netsh", "interface", "ipv6", "show", "address"], timeout=5)
	if not ok or not out.strip():
		return []
	# O cabecalho "Interface N: Nome" fica numa linha, e os enderecos
	# aparecem depois de uma linha em branco e de uma tabela - ou seja,
	# em blocos SEPARADOS quando se divide por linha em branco. Por isso
	# nao basta procurar o nome da interface e pegar so aquele bloco: e
	# preciso capturar tudo entre este cabecalho e o proximo cabecalho de
	# interface (que sempre tem o formato "<algo> <numero>: <nome>").
	iface_esc = re.escape(iface)
	pat = re.compile(
		r"\S+\s+\d+\s*:\s*" + iface_esc + r"\s*\r?\n"
		r"(.*?)(?=\r?\n\S+\s+\d+\s*:\s*\S|\Z)", re.I | re.S)
	m = pat.search(out)
	if not m:
		return []
	# Le a ultima coluna de cada linha da tabela (a coluna "Address").
	# Nao usamos regex de formato IPv6 aqui porque enderecos link-local
	# usam notacao compacta "::" que uma regex simples nao reconhece bem;
	# como o layout e sempre em colunas, pegar o ultimo token de cada
	# linha que contenha ":" e muito mais confiavel.
	addrs = []
	for line in m.group(1).splitlines():
		line = line.strip()
		if not line:
			continue
		tok = line.split()[-1]
		if ":" in tok:
			addrs.append(tok.split("%")[0])
	return addrs


def get_ipv6(iface):
	addrs = _ipv6_addr_list(iface)
	globals_ = [a for a in addrs if not a.lower().startswith("fe80")]
	if globals_:
		return globals_[0]
	link_local = [a for a in addrs if a.lower().startswith("fe80")]
	return link_local[0] if link_local else None


def ipv6_addresses(iface):
	"""Como get_ipv6(), mas separa endereco global de link-local em vez de
	devolver so um. Usado pelo modulo de diagnostico IPv6, que precisa
	saber a diferenca entre 'tem endereco de verdade' e 'so tem link-local
	(nunca saiu da rede local)'."""
	addrs = _ipv6_addr_list(iface)
	globals_ = [a for a in addrs if not a.lower().startswith("fe80")]
	link_local = [a for a in addrs if a.lower().startswith("fe80")]
	return {
		"global": globals_[0] if globals_ else None,
		"link_local": link_local[0] if link_local else None,
	}


def ipv6_default_route():
	"""Verifica se existe uma rota padrao IPv6 (prefixo '::/0') com um
	gateway de verdade (nao 'on-link'). Isso indica que algum roteador na
	rede local esta anunciando (via Router Advertisement) que sabe como
	encaminhar trafego IPv6 para fora - mesmo que este computador nao
	tenha recebido um endereco global proprio.
	Deteccao estrutural (independente de idioma): a linha da tabela de
	rotas que contem o prefixo '::/0' sempre termina com a coluna
	Gateway/Interface. Quando ha um gateway real, essa coluna e um
	endereco IPv6 (contem ':'); quando a rota e 'on-link', a coluna e
	apenas o nome da interface (normalmente sem ':')."""
	ok, out = run(["netsh", "interface", "ipv6", "show", "route"], timeout=5)
	if not ok or not out.strip():
		return False, None
	for line in out.splitlines():
		line = line.strip()
		if not line or "::/0" not in line:
			continue
		parts = line.split()
		if not parts:
			continue
		last = parts[-1]
		if ":" in last:
			return True, last
	return False, None


# Alvos publicos conhecidos e estaveis usados so para testar se existe
# saida real para a internet via IPv6 (conexao TCP crua, sem DNS). Mais
# de um alvo/porta para nao dar falso negativo se um deles estiver fora
# do ar ou bloqueado especificamente.
_IPV6_PROBE_TARGETS = [
	("2606:4700:4700::1111", 443, "Cloudflare"),
	("2001:4860:4860::8888", 443, "Google"),
	("2620:fe::fe", 443, "Quad9"),
]


def ipv6_connectivity_test(timeout=2.5):
	"""Tenta abrir uma conexao TCP crua (sem DNS) contra alguns enderecos
	IPv6 publicos conhecidos e estaveis. Devolve (True, nome_do_provedor)
	se algum responder, ou (False, None) se todos falharem - o que indica
	que o IPv6 desta maquina, mesmo que tenha endereco, nao consegue
	realmente sair para a internet."""
	for ip, port, name in _IPV6_PROBE_TARGETS:
		s = None
		try:
			s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
			s.settimeout(timeout)
			s.connect((ip, port, 0, 0))
			return True, name
		except Exception:
			continue
		finally:
			if s is not None:
				try:
					s.close()
				except Exception:
					pass
	return False, None


def ipv6_dns_test(host, timeout=3.0):
	"""Testa se o DNS resolve endereco IPv6 (AAAA) para 'host' e, se
	resolver, tenta uma conexao TCP real contra o endereco obtido - assim
	da para distinguir 'DNS ok mas conexao quebrada' de 'DNS nem resolve'.
	Devolve dict com resolved (bool), address (str ou None) e connected
	(bool ou None, None quando nem chegou a tentar por falta de endereco)."""
	try:
		infos = socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM)
	except Exception:
		return {"resolved": False, "address": None, "connected": None}
	if not infos:
		return {"resolved": False, "address": None, "connected": None}
	addr = infos[0][4][0]
	connected = False
	s = None
	try:
		s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect((addr, 443, 0, 0))
		connected = True
	except Exception:
		connected = False
	finally:
		if s is not None:
			try:
				s.close()
			except Exception:
				pass
	return {"resolved": True, "address": addr, "connected": connected}


def hostname():
	try:
		return socket.gethostname()
	except Exception:
		return None


def arp_table():
	# Le a tabela ARP dos DOIS jeitos e funde os dois: nativo
	# (GetIpNetTable, ver sysutils.py) primeiro, "arp -a" (texto,
	# subprocesso) sempre depois como reforco - nao so quando o nativo
	# falha.
	#
	# Descoberto ao vivo no hardware do usuario: GetIpNetTable pode
	# devolver uma tabela INCOMPLETA sem erro nenhum (sem lancar
	# excecao, sem devolver None) - um IP que "arp -a" sempre mostrava
	# certinho simplesmente nao aparecia na leitura nativa, e isso se
	# repetiu mesmo depois de varias tentativas de corrigir por outros
	# angulos (pausa antes de ler, capturar o MAC direto do SendARP).
	# "arp -a" e mais lento (processo externo) mas se provou o mais
	# CONFIAVEL dos dois nesse caso - por isso agora sempre roda os
	# dois e funde o resultado, em vez de confiar cegamente no nativo so
	# porque ele nao devolveu erro.
	nativa = arp_table_native() or {}
	ok, out = run(["arp", "-a"], timeout=5)
	if ok:
		for m in re.finditer(rx.IP + r"\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out):
			nativa.setdefault(m.group(1), m.group(2).replace("-", ":"))
	return nativa


def mac_vendor(mac, oui_cache_path=None):
	"""Identifica o fabricante pelos 3 primeiros bytes do MAC (OUI),
	consultando a base COMPLETA da IEEE (~33 mil fabricantes) baixada
	sob demanda por download_oui_database() e carregada por
	load_oui_database() (uma unica vez por sessao do NVDA, nao recarrega
	a cada consulta). So funciona depois que a base tiver sido baixada
	pelo menos uma vez (ver "Atualizar Base de Fabricantes Completa" no
	submenu de Varredura de Dispositivos) - sem isso, ou se
	oui_cache_path nao for passado, devolve None sempre.

	Devolve o nome do fabricante, ou None se o prefixo nao for
	encontrado (ou a base nunca foi baixada) - quem chama deve tratar
	None como "fabricante nao identificado", nao como erro."""
	if not mac or not oui_cache_path:
		return None
	partes = mac.upper().replace("-", ":").split(":")
	if len(partes) < 3:
		return None
	oui = ":".join(partes[:3])
	return load_oui_database(oui_cache_path).get(oui)


# Base completa da IEEE (nunca baixada por padrao) - carregada na
# memoria uma unica vez por sessao do NVDA, depois disso load_oui_database()
# so devolve o que ja esta aqui, sem reler o arquivo do disco toda vez.
_oui_full_cache = None


def _oui_meta_path(dest_path):
	"""Caminho do arquivinho de metadados que guarda o cabecalho
	Last-Modified devolvido pelo servidor na ultima vez que a base foi
	baixada com sucesso - fica ao lado do cache principal (mesmo nome
	+ ".meta"). E o que permite o download CONDICIONAL: da proxima vez,
	mandamos essa data de volta pro servidor (If-Modified-Since) e ele
	responde so "nao mudou nada" (HTTP 304) se for o caso, sem reenviar
	os ~3 MB inteiros."""
	return dest_path + ".meta"


def download_oui_database(dest_path, timeout=60, force=False):
	"""Baixa a base COMPLETA e oficial de fabricantes da IEEE
	(oui.csv, ~3 MB, ~33 mil entradas) e salva em dest_path. So roda
	quando explicitamente pedido pelo usuario (ver menu "Atualizar Base
	de Fabricantes Completa") - nunca automatico, nunca em segundo
	plano sem aviso, exatamente pelo mesmo motivo que os Detalhes
	Adicionais Online tambem sao uma acao separada: usa internet e baixa
	um arquivo de verdade, entao o usuario decide quando.

	DOWNLOAD CONDICIONAL: antes de baixar de verdade, manda o cabecalho
	If-Modified-Since com a data que o servidor informou (Last-Modified)
	na ultima vez que baixamos com sucesso (guardada num arquivinho de
	metadados ao lado do cache - ver _oui_meta_path). Se o servidor
	confirmar que o arquivo nao mudou desde entao (HTTP 304), NAO baixa
	os ~3 MB de novo a toa - so informa que ja estava atualizado. Se o
	servidor nao suportar isso por algum motivo, degrada sozinho pro
	comportamento de sempre (baixa completo), sem quebrar nada.
	force=True pula essa checagem e forca o download completo mesmo
	assim.

	Mesmo User-Agent de navegador ja usado pros outros servicos deste
	projeto (Cloudflare, macvendors.com) - APIs publicas costumam
	bloquear o User-Agent padrao do Python.

	Devolve (ok, atualizou, erro):
	- (True, True, None): baixou dado novo com sucesso
	- (True, False, None): ja estava atualizado, nao precisou baixar de novo
	- (False, False, motivo): falha real (sem internet, timeout, arquivo
	  corrompido, etc.) - nunca falha silenciosamente."""
	global _oui_full_cache
	meta_path = _oui_meta_path(dest_path)
	headers = {"User-Agent": _CF_USER_AGENT}
	if not force and os.path.exists(dest_path) and os.path.exists(meta_path):
		try:
			with open(meta_path, "r", encoding="utf-8") as f:
				ultima_data = f.read().strip()
			if ultima_data:
				headers["If-Modified-Since"] = ultima_data
		except Exception:
			pass
	try:
		req = urllib.request.Request(
			"https://standards-oui.ieee.org/oui/oui.csv", headers=headers)
		with urllib.request.urlopen(req, timeout=timeout) as r:
			dados = r.read()
			nova_data = r.headers.get("Last-Modified")
		if not dados:
			return False, False, "resposta vazia"
		with open(dest_path, "wb") as f:
			f.write(dados)
		if nova_data:
			try:
				with open(meta_path, "w", encoding="utf-8") as f:
					f.write(nova_data)
			except Exception:
				pass  # nao impede o download de valer - so perde a otimizacao da proxima vez
		# Forca a proxima consulta a reler o arquivo novo do disco, em
		# vez de continuar usando uma versao antiga que ja estava na
		# memoria de uma sessao anterior do NVDA.
		_oui_full_cache = None
		# Verificacao de sanidade: confirma que o arquivo baixado
		# realmente vira um numero razoavel de fabricantes depois do
		# parsing, antes de aceitar como valido. Protege contra download
		# incompleto (conexao caiu no meio) ou corrompido (a IEEE
		# devolveu uma pagina de erro em HTML em vez do CSV, por
		# exemplo) - sem isso, um arquivo pequeno/invalido ficaria
		# salvo sem NENHUM erro aparecer, e o usuario so notaria bem
		# depois, quando a Varredura continuasse sem achar fabricante
		# nenhum.
		tabela = load_oui_database(dest_path)
		if len(tabela) < 1000:
			try:
				os.remove(dest_path)
				os.remove(meta_path)
			except OSError:
				pass
			_oui_full_cache = None
			return False, False, (
				f"arquivo baixado parece incompleto ou inválido "
				f"({len(tabela)} fabricantes encontrados, esperava milhares)"
			)
		return True, True, None
	except urllib.error.HTTPError as e:
		if e.code == 304:
			# O servidor confirmou: nao mudou nada desde a ultima vez.
			# Nao precisou baixar os ~3 MB inteiros so pra descobrir
			# isso - exatamente o ganho do download condicional.
			return True, False, None
		return False, False, f"HTTP {e.code}"
	except Exception as e:
		return False, False, f"{type(e).__name__}: {e}"


def oui_database_info(path):
	"""Informacoes sobre o cache local da base completa - existe? quando
	foi baixado pela ultima vez? quantas entradas tem? Usa a propria
	data de MODIFICACAO do arquivo como "ultima atualizacao" - toda
	atualizacao sobrescreve o mesmo arquivo (ver download_oui_database),
	entao o mtime dele ja reflete isso direto, sem precisar de nenhum
	arquivo de metadados separado pra guardar essa data.

	Devolve (existe, timestamp_ultima_atualizacao_ou_None, num_entradas)
	- timestamp no formato de time.time() (epoch), pra quem chama
	formatar do jeito que quiser."""
	if not os.path.exists(path):
		return False, None, 0
	try:
		mtime = os.path.getmtime(path)
	except OSError:
		mtime = None
	tabela = load_oui_database(path)
	return True, mtime, len(tabela)


def load_oui_database(path):
	"""Carrega o cache local da base completa (oui.csv baixado por
	download_oui_database) pra memoria - uma unica vez por sessao do
	NVDA, chamadas seguintes devolvem o que ja foi carregado sem reler
	o arquivo. Formato oficial da IEEE: CSV com colunas
	Registry,Assignment,Organization Name,Organization Address -
	"Assignment" e o OUI sem separador (ex.: "0050C2").

	Devolve um dict OUI ("XX:XX:XX") -> nome do fabricante, ou {} se o
	arquivo nao existir ainda (nunca baixado) ou nao puder ser lido -
	nunca lanca excecao, quem chama trata {} como "base completa
	indisponivel ainda", igual a lista local vazia seria tratada."""
	global _oui_full_cache
	if _oui_full_cache is not None:
		return _oui_full_cache
	tabela = {}
	try:
		with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
			leitor = csv.reader(f)
			next(leitor, None)  # pula o cabecalho (Registry,Assignment,...)
			for linha in leitor:
				if len(linha) < 3:
					continue
				assignment = linha[1].strip().upper()
				nome = linha[2].strip()
				if len(assignment) == 6 and nome:
					oui = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}"
					tabela[oui] = nome
	except Exception:
		tabela = {}
	_oui_full_cache = tabela
	return tabela


def load_dns_list(path):
	"""Le a lista COMPLETA de servidores DNS que a Busca de Melhor DNS
	testa (um IPv4 por linha, arquivo texto simples) - o usuario gerencia
	essa lista inteira (adicionar, editar, remover LIVREMENTE, inclusive
	os que vieram por padrao) via "Gerenciar Servidores DNS" (ver
	save_dns_list). Nao existe mais uma lista fixa separada embutida no
	codigo - a partir da primeira vez que o addon roda, este arquivo e a
	UNICA fonte de verdade.

	Na PRIMEIRA vez (arquivo ainda nao existe), semeia o arquivo com
	DEFAULT_DNS_CANDIDATES (a lista de provedores publicos ja
	pesquisada), pra nao comecar vazio - dai em diante, mesmo esses
	iniciais podem ser removidos pelo usuario se ele quiser, sem
	reaparecerem sozinhos depois.

	Ignora linhas vazias e linhas que nao sejam um IPv4 valido ao ler
	(defesa extra, mesmo que save_dns_list ja valide antes de salvar -
	um arquivo editado na mao por fora do addon, por exemplo, poderia
	ter conteudo invalido).

	Devolve uma lista de IPs (str), na ordem do arquivo, ou [] se nao
	existir, nao puder ser lido, NEM puder ser semeado (ex.: sem
	permissao de escrita) - nunca lanca excecao; quem chama deve avisar
	quando a lista vier vazia, ja que nesse caso a busca nao teria
	nenhum candidato pra testar."""
	if not os.path.exists(path):
		try:
			with open(path, "w", encoding="utf-8") as f:
				f.write("\n".join(DEFAULT_DNS_CANDIDATES) + "\n")
		except Exception:
			return []
	try:
		with open(path, "r", encoding="utf-8", errors="replace") as f:
			linhas = f.read().splitlines()
	except Exception:
		return []
	ips = []
	for linha in linhas:
		ip = linha.strip()
		if not ip:
			continue
		try:
			socket.inet_aton(ip)
			ips.append(ip)
		except OSError:
			continue
	return ips


def save_dns_list(path, texto):
	"""Salva a lista de servidores DNS (ver load_dns_list) a partir do
	texto cru editado no dialogo de gerenciamento (um IP por linha).
	Valida CADA linha nao-vazia como IPv4, E rejeita linhas DUPLICADAS
	dentro da PROPRIA lista (nao faz sentido testar o mesmo servidor
	duas vezes) - tudo ou nada: se alguma linha nao passar, NADA e
	salvo (evita salvar uma lista parcialmente valida sem o usuario
	perceber qual linha especifica deu problema), e a mensagem diz
	exatamente qual linha e por que.

	Devolve (True, None) se salvou com sucesso (mesmo que a lista final
	fique vazia - o usuario pode querer limpar tudo; quem chama deve
	avisar sobre isso separadamente), ou (False, mensagem_pronta) com
	uma explicacao completa (IP invalido OU duplicado) se alguma linha
	nao validou."""
	ips = []
	vistos = set()
	for linha in texto.splitlines():
		ip = linha.strip()
		if not ip:
			continue
		try:
			socket.inet_aton(ip)
		except OSError:
			return False, _("\"{ip}\" não é um endereço IPv4 válido.").format(ip=ip)
		if ip in vistos:
			return False, _(
				"\"{ip}\" está duplicado - apareceu mais de uma vez na lista."
			).format(ip=ip)
		vistos.add(ip)
		ips.append(ip)
	try:
		with open(path, "w", encoding="utf-8") as f:
			f.write("\n".join(ips))
			if ips:
				f.write("\n")
	except Exception:
		return False, None
	return True, None


def ping_parse(host, count=4, timeout=15):
	"""Faz o ping e devolve um dict com media/min/max/jitter/perda/ttl, ou
	None se o comando falhar por completo (nesse caso quem chama deve
	cair para a reserva de texto ping.exe/regex de idioma unico)."""
	ok, out = run(["ping", "-n", str(count), host], timeout=timeout)
	if not ok:
		return None
	dest_m = rx.RX_PING_DEST_IP.search(out)
	dest_ip = dest_m.group(1) if dest_m else host
	# Extrai o tempo de cada linha de resposta individualmente.
	# Busca "=Nms" ou "=N ms" (russo usa espaco antes de ms/мс). O rotulo
	# que vem antes (time=, tiempo=, Zeit=, temps=, durata=, время=) varia,
	# mas o formato "=NUMEROms" nunca muda em nenhuma versao do Windows.
	times = [int(t) for t in re.findall(r"=(\d+)\s*[mм][sс]", out, re.I)]
	recv = len(times)
	# Pacotes enviados/recebidos de verdade, segundo o proprio ping.exe
	# (linha-resumo), em vez de assumir que "sent" == count pedido - mais
	# fiel caso o comando seja interrompido ou o Windows reporte diferente.
	summary_m = rx.RX_PING_SUMMARY.search(out)
	sent = int(summary_m.group(1)) if summary_m else count
	if recv == 0:
		return {"avg": None, "loss": 100, "recv": 0, "sent": sent, "dest_ip": dest_ip}
	avg  = round(sum(times) / recv)
	loss = round(((count - recv) / count) * 100)
	mn = min(times)
	mx = max(times)
	# Jitter: media da variacao absoluta entre respostas consecutivas
	if recv >= 2:
		deltas = [abs(times[i] - times[i-1]) for i in range(1, recv)]
		jitter = round(sum(deltas) / len(deltas), 1)
		std = round(statistics.stdev(times), 1)
	else:
		jitter = 0
		std = 0.0
	ttls = [int(t) for t in rx.RX_PING_TTL.findall(out)]
	ttl = ttls[0] if ttls else None
	# Veredito geral: perda de pacotes pesa mais que jitter (qualquer
	# perda ja torna a conexao pouco confiavel para uso em tempo real,
	# independente de quao estavel for a latencia quando ha resposta).
	if loss > 0:
		status = "unstable"
	elif jitter <= 15:
		status = "excellent"
	elif jitter <= 40:
		status = "stable"
	else:
		status = "unstable"
	return {"avg": avg, "loss": loss, "recv": recv, "sent": sent, "dest_ip": dest_ip,
		"min": mn, "max": mx, "jitter": jitter, "std": std, "ttl": ttl, "status": status}


def tcp_ping(host, port, count=4, timeout_per_conn=3):
	""""Ping" TCP: abre e fecha uma conexao TCP na porta especificada,
	count vezes, cronometrando cada tentativa - o equivalente ao ping
	ICMP tradicional, mas testando alcance de uma PORTA especifica (util
	quando ICMP esta bloqueado por firewall mas a porta em si responde,
	ou quando o que importa e testar o servico de verdade - ex.: HTTPS na
	443 - nao so se o host esta de pe). Socket puro da biblioteca padrao -
	sem PowerShell, sem Administrador, sem processo externo nenhum.

	Devolve um dict no MESMO FORMATO de ping_parse() acima (avg/min/max/
	jitter/std/loss/recv/sent/dest_ip/status), exceto "ttl", que fica
	sempre None (TCP nao expoe TTL do jeito que ICMP expoe) - dessa forma
	a tela de resultado do Ping Inteligente reaproveita a MESMA logica de
	apresentacao pros dois modos, sem duplicar codigo (su.fmt ja descarta
	sozinho qualquer linha com valor None, entao a linha de TTL some
	naturalmente nesse modo, sem precisar de nenhum "if" especial)."""
	times = []
	recv = 0
	dest_ip = host
	for _i in range(count):
		inicio = time.perf_counter()
		try:
			with socket.create_connection((host, port), timeout=timeout_per_conn) as s:
				dest_ip = s.getpeername()[0]
			times.append((time.perf_counter() - inicio) * 1000)
			recv += 1
		except OSError:
			pass
	sent = count
	if recv == 0:
		return {"avg": None, "loss": 100, "recv": 0, "sent": sent, "dest_ip": dest_ip}
	avg = round(sum(times) / recv)
	loss = round(((sent - recv) / sent) * 100)
	mn = round(min(times))
	mx = round(max(times))
	if recv >= 2:
		deltas = [abs(times[i] - times[i - 1]) for i in range(1, recv)]
		jitter = round(sum(deltas) / len(deltas), 1)
		std = round(statistics.stdev(times), 1)
	else:
		jitter = 0
		std = 0.0
	if loss > 0:
		status = "unstable"
	elif jitter <= 15:
		status = "excellent"
	elif jitter <= 40:
		status = "stable"
	else:
		status = "unstable"
	return {"avg": avg, "loss": loss, "recv": recv, "sent": sent, "dest_ip": dest_ip,
		"min": mn, "max": mx, "jitter": jitter, "std": std, "ttl": None, "status": status}


def _build_dns_query(domain):
	# Monta manualmente um pacote de consulta DNS (tipo A) sobre UDP,
	# seguindo a RFC 1035. Nao usamos nenhuma biblioteca externa (como
	# dnspython) de proposito: a biblioteca padrao ja e suficiente e evita
	# adicionar uma dependencia extra ao addon.
	transaction_id = random.randint(0, 65535)
	flags = 0x0100  # consulta padrao, recursao desejada
	header = struct.pack(">HHHHHH", transaction_id, flags, 1, 0, 0, 0)
	qname = b"".join(
		bytes([len(part)]) + part.encode("ascii") for part in domain.split(".")
	) + b"\x00"
	question = qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
	return header + question


def measure_dns_latency(server_ip, domain="example.com", timeout=2.0):
	"""Mede o tempo de resposta (RTT), em milissegundos, de um servidor DNS
	especifico. Envia uma consulta DNS crua via UDP diretamente aquele
	servidor (sem passar pelo resolver padrao do Windows), entao o tempo
	medido reflete exclusivamente aquele servidor. Devolve None se o
	servidor nao responder dentro do tempo limite."""
	try:
		query = _build_dns_query(domain)
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
			s.settimeout(timeout)
			start = time.perf_counter()
			s.sendto(query, (server_ip, 53))
			s.recvfrom(512)
			elapsed_ms = (time.perf_counter() - start) * 1000
			return round(elapsed_ms)
	except Exception:
		return None


def measure_dns_latency_multi(server_ip, domain="example.com", samples=5, timeout=2.0):
	"""Mede a ESTABILIDADE de um servidor DNS, nao so a velocidade - faz
	"samples" consultas em SEQUENCIA (reaproveitando measure_dns_latency
	pra cada uma) e devolve media/jitter/desvio padrao/perda, no mesmo
	formato ja usado pela Ping Inteligente e pelo Monitor de Conexao
	(avg/loss/recv/sent/jitter/std) - consistente com o resto do addon.

	Uma unica consulta pode cair numa "sorte" ou "azar" momentaneo do
	servidor ou da rede; um servidor com media baixa mas jitter alto
	(varia muito entre uma consulta e outra) pode ser pior de usar no
	dia a dia do que um com media um pouco maior mas estavel - essa
	funcao e o que permite enxergar essa diferenca, que uma consulta so
	nunca mostraria.

	Devolve um dict {"avg", "min", "max", "jitter", "std", "loss",
	"recv", "sent"} - "avg"/"jitter"/"std" vem None se NENHUMA consulta
	respondeu (nesse caso "loss" sempre vem 100)."""
	tempos = []
	for _i in range(samples):
		t = measure_dns_latency(server_ip, domain, timeout)
		if t is not None:
			tempos.append(t)
	sent = samples
	recv = len(tempos)
	if recv == 0:
		return {"avg": None, "min": None, "max": None, "jitter": None,
			"std": None, "loss": 100, "recv": 0, "sent": sent}
	avg = round(sum(tempos) / recv)
	loss = round(((sent - recv) / sent) * 100)
	if recv >= 2:
		deltas = [abs(tempos[i] - tempos[i - 1]) for i in range(1, recv)]
		jitter = round(sum(deltas) / len(deltas), 1)
		std = round(statistics.stdev(tempos), 1)
	else:
		jitter = 0.0
		std = 0.0
	return {"avg": avg, "min": min(tempos), "max": max(tempos), "jitter": jitter,
		"std": std, "loss": loss, "recv": recv, "sent": sent}


def find_best_dns(candidates=None, extra_ip=None, domain="example.com", timeout=2.0,
		max_workers=20, samples=1, finalists=8):
	"""Busca o DNS mais rapido e ESTAVEL entre varios servidores publicos
	conhecidos, em DUAS FASES:

	FASE 1 (rapida, uma consulta por servidor, TODOS os candidatos em
	paralelo): descarta rapidamente quem nem responde, sem gastar tempo
	testando de verdade servidores que provavelmente nem vao entrar na
	consideracao final. E o mesmo teste de sempre (measure_dns_latency).

	FASE 2 (profunda, so nos "finalists" primeiros colocados da fase 1 +
	extra_ip, se "samples" > 1): repete a consulta "samples" vezes pra
	cada um desses poucos (measure_dns_latency_multi), medindo jitter e
	perda alem da media - a fase que realmente da uma nocao de
	ESTABILIDADE, sem pagar o custo de fazer isso pra todos os ~28
	candidatos, a maioria dos quais nem chegaria perto do topo mesmo.

	Se samples<=1, pula a fase 2 inteira e devolve so o resultado da
	fase 1 (comportamento identico ao de antes desta funcao ganhar
	fases, pra quem nao quer pagar o tempo extra).

	candidates: lista de IPs a testar; default DEFAULT_DNS_CANDIDATES (a
	lista curada acima). extra_ip: um IP adicional para incluir no teste
	mesmo que nao esteja na lista curada - usado por quem chama para
	garantir que o DNS ATUALMENTE em uso tambem seja medido e apareca na
	comparacao, mesmo quando for um servidor desconhecido (ex.: o proprio
	roteador, ou o resolver do provedor de internet local). Como
	extra_ip e sempre o DNS atual do usuario, ele SEMPRE avanca pra fase
	2 (mesmo que nao tenha ficado entre os "finalists" primeiros da fase
	1), pra a comparacao final com o atual ser sempre justa e completa.

	Devolve uma lista de dicts (ip, latency_ms, provider, e - so quando
	samples>1 - jitter_ms/std_ms/loss_pct), ordenada do mais rapido para
	o mais lento pela media (latency_ms). Servidores que nao
	responderem ficam de fora."""
	ips = list(candidates) if candidates is not None else list(DEFAULT_DNS_CANDIDATES)
	if extra_ip and extra_ip not in ips:
		ips.append(extra_ip)

	# --- Fase 1: uma consulta rapida em todos, so pra descartar quem
	# nem responde e ordenar os que respondem.
	fase1 = []
	with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
		futuros = {ex.submit(measure_dns_latency, ip, domain, timeout): ip for ip in ips}
		for fut in concurrent.futures.as_completed(futuros):
			ip = futuros[fut]
			try:
				latencia = fut.result()
			except Exception:
				latencia = None
			if latencia is not None:
				fase1.append({"ip": ip, "latency_ms": latencia, "provider": identify_dns_provider(ip)})
	fase1.sort(key=lambda r: r["latency_ms"])

	if samples <= 1:
		return fase1

	# --- Fase 2: so os primeiros colocados da fase 1 (+ o DNS atual,
	# garantido, mesmo se nao ficou entre eles) recebem o teste
	# profundo de estabilidade.
	ips_finalistas = [r["ip"] for r in fase1[:finalists]]
	if extra_ip and extra_ip not in ips_finalistas and any(r["ip"] == extra_ip for r in fase1):
		ips_finalistas.append(extra_ip)
	if not ips_finalistas:
		return fase1

	fase2 = []
	with concurrent.futures.ThreadPoolExecutor(max_workers=len(ips_finalistas)) as ex:
		futuros = {
			ex.submit(measure_dns_latency_multi, ip, domain, samples, timeout): ip
			for ip in ips_finalistas
		}
		for fut in concurrent.futures.as_completed(futuros):
			ip = futuros[fut]
			try:
				stats = fut.result()
			except Exception:
				stats = None
			if stats and stats["avg"] is not None:
				fase2.append({
					"ip": ip,
					"latency_ms": stats["avg"],
					"provider": identify_dns_provider(ip),
					"jitter_ms": stats["jitter"],
					"std_ms": stats["std"],
					"loss_pct": stats["loss"],
				})
	fase2.sort(key=lambda r: r["latency_ms"])
	return fase2


def identify_dns_provider(ip):
	"""Tenta identificar a quem pertence um servidor DNS. Primeiro procura
	numa lista de servicos publicos conhecidos (Google, Cloudflare, etc.);
	se o IP nao estiver nela, tenta um DNS reverso (PTR) no proprio IP do
	servidor, o que costuma revelar o dominio do provedor de internet local
	(ex.: algo como "dns.provedor.com.br"). Devolve None se nada for
	encontrado por nenhum dos dois metodos."""
	known = KNOWN_DNS_PROVIDERS.get(ip)
	if known:
		return known
	try:
		host, _, _ = socket.gethostbyaddr(ip)
		return host
	except Exception:
		return None


# ---------------------------------------------------------------------------
# Aplicar DNS personalizado, com alternativa de DNS via HTTPS (DoH)
# ---------------------------------------------------------------------------
#
# So os provedores publicos abaixo tem endpoint DoH conhecido e documentado.
# Nao e possivel "adivinhar" um endpoint DoH para um servidor qualquer (o
# IP do roteador, ou o resolver do provedor de internet local, por
# exemplo) - o protocolo exige uma URL especifica por servidor, que so o
# proprio provedor divulga. Por isso o Modo Seguro so fica disponivel
# quando o IP digitado bate com um destes.
DOH_TEMPLATES = {
	"8.8.8.8":         "https://dns.google/dns-query",
	"8.8.4.4":         "https://dns.google/dns-query",
	"1.1.1.1":         "https://cloudflare-dns.com/dns-query",
	"1.0.0.1":         "https://cloudflare-dns.com/dns-query",
	"9.9.9.9":         "https://dns.quad9.net/dns-query",
	"149.112.112.112": "https://dns.quad9.net/dns-query",
	"208.67.222.222":  "https://doh.opendns.com/dns-query",
	"208.67.220.220":  "https://doh.opendns.com/dns-query",
	"94.140.14.14":    "https://dns.adguard-dns.com/dns-query",
	"94.140.15.15":    "https://dns.adguard-dns.com/dns-query",
	"185.228.168.9":   "https://doh.cleanbrowsing.org/doh/family-filter/",
	"185.228.169.9":   "https://doh.cleanbrowsing.org/doh/family-filter/",
	"76.76.2.0":       "https://freedns.controld.com/p2",
	"76.76.19.19":     "https://freedns.controld.com/p2",
}


def doh_template_for(ip):
	"""Devolve a URL do endpoint DoH conhecido para este IP, ou None se o
	servidor nao for um dos provedores publicos documentados acima."""
	return DOH_TEMPLATES.get(ip)


def test_doh(ip, domain="example.com", timeout=3.0):
	"""Testa se um servidor de DNS conhecido responde por DNS-over-HTTPS
	(RFC 8484), fazendo uma consulta real via HTTPS - sem alterar nenhuma
	configuracao do sistema, no mesmo espirito de measure_dns_latency (que
	faz o equivalente para DNS tradicional via porta 53). Devolve True se
	uma resposta DNS valida chegou pela porta 443, False se a consulta
	falhar, e None se este IP nao tiver um endpoint DoH conhecido (nesse
	caso nem tentamos - ver doh_template_for)."""
	template = doh_template_for(ip)
	if not template:
		return None
	try:
		import base64
		consulta = _build_dns_query(domain)
		# RFC 8484, metodo GET: a consulta DNS crua (o mesmo pacote binario
		# usado em measure_dns_latency) vai em base64url sem padding, no
		# parametro "dns" da URL.
		b64 = base64.urlsafe_b64encode(consulta).rstrip(b"=").decode("ascii")
		req = urllib.request.Request(
			f"{template}?dns={b64}",
			headers={"Accept": "application/dns-message", "User-Agent": "Mozilla/5.0 NVDA-NetworkTools/9"},
		)
		with urllib.request.urlopen(req, timeout=timeout) as r:
			corpo = r.read()
			# Um cabecalho DNS valido tem 12 bytes - qualquer resposta menor
			# que isso nao pode ser uma resposta DNS de verdade.
			return r.status == 200 and len(corpo) >= 12
	except Exception:
		return False


def apply_dns(iface, primario, secundario=None):
	"""Define `primario` como servidor DNS primario da interface `iface`
	e, se informado, `secundario` como o segundo.

	IMPORTANTE: "netsh interface ip set dns ... addr=X" SUBSTITUI toda a
	lista de servidores DNS da interface por um UNICO endereco - ele nao
	preserva nenhum servidor secundario que ja estivesse configurado
	antes. Por isso esta funcao aceita um `secundario` explicito: quem
	chama (globalPlugins/networkTools.py) deve descobrir o secundario que
	ja estava configurado ANTES de chamar esta funcao (com
	get_ip_config(), por exemplo) e repassa-lo aqui se quiser manter essa
	configuracao - caso contrario, aplicar so o primario apaga
	silenciosamente o que havia antes.

	Devolve (rc_primario, saida_primario, rc_secundario_ou_None,
	saida_secundario_ou_None). Os dois ultimos valores vem como None
	quando `secundario` nao for informado, ou quando o primario falhar
	(nao faz sentido tentar o secundario se o primario nem foi aplicado)."""
	rc, out = run_rc(["netsh", "interface", "ip", "set", "dns",
		f"name={iface}", "source=static", f"addr={primario}", "register=primary"], timeout=15)
	if rc != 0 or not secundario:
		return rc, out, None, None
	rc2, out2 = run_rc(["netsh", "interface", "ip", "add", "dns",
		f"name={iface}", f"addr={secundario}", "index=2"], timeout=15)
	return rc, out, rc2, out2


def enable_doh(ip, template):
	"""Registra `ip` como um servidor de DNS criptografado conhecido do
	Windows (recurso nativo disponivel a partir do Windows 10 21H1 /
	Windows 11), usando o endpoint DoH informado. `udpfallback=no` e
	proposital: garante que a consulta REALMENTE va por HTTPS (porta 443)
	- sem isto, o Windows poderia voltar a tentar a porta 53 (a mesma que
	o roteador esta bloqueando) em caso de qualquer instabilidade,
	escondendo o problema em vez de contorna-lo de verdade.

	Se o Windows nao suportar este recurso (versoes mais antigas do
	Windows 10), o comando falha com um returncode diferente de zero -
	quem chama esta funcao deve tratar isso como "este Windows nao tem
	suporte nativo a DoH", nao como um erro de configuracao do usuario.
	Devolve (returncode, saida_do_comando)."""
	return run_rc(["netsh", "dns", "add", "encryption",
		f"server={ip}", f"dohtemplate={template}", "autoupgrade=yes", "udpfallback=no"], timeout=15)


# Endpoints publicos e gratuitos do Cloudflare que alimentam o speedtest
# oficial deles (speed.cloudflare.com). Nao exigem chave de API nem
# cadastro: qualquer requisicao GET/POST simples e suficiente. Ver
# https://speed.cloudflare.com - o addon so baixa/envia um bloco de bytes
# e cronometra o tempo, exatamente como o site oficial faz.
_CF_DOWN_URL = "https://speed.cloudflare.com/__down?bytes={n}"
_CF_UP_URL = "https://speed.cloudflare.com/__up"
# Um User-Agent que se identifica como "NVDA-NetworkTools" e um sinal
# claro de bot/script pra qualquer checagem automatica de trafego -
# nenhum navegador de verdade manda algo assim. O endpoint de download/
# upload tolerava isso (sao so bytes crus, sem checagem rigorosa), mas o
# de METADADOS (que devolve IP/localizacao - dado "de valor") parece
# aplicar uma checagem de bot mais rigorosa e barra esse UA com 403
# Forbidden - encontrado ao vivo no hardware do usuario. Usar um
# User-Agent de navegador real (a mesma tecnica que qualquer cliente
# HTTP nao-navegador precisa pra falar com endpoints protegidos por
# essas checagens) resolve isso sem exigir nada alem de um cabecalho
# diferente.
_CF_USER_AGENT = (
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
	"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
# Referer que o proprio site oficial de teste de velocidade do
# Cloudflare envia ao consultar esses mesmos endpoints - inclui-lo deixa
# a requisicao mais parecida com a de um navegador de verdade acessando
# a pagina real, reduzindo ainda mais a chance de uma checagem de bot
# barrar a chamada.
_CF_REFERER = "https://speed.cloudflare.com/"
# Endpoint de metadados do Cloudflare - o MESMO que o site oficial de
# teste de velocidade deles consulta para mostrar IP/datacenter/ASN.
# Devolve JSON de verdade (nao texto pra parsear), com campos sempre em
# ingles independente de regiao: clientIp, colo (codigo IATA do
# datacenter que atendeu, ex.: "GRU" = Sao Paulo), httpProtocol, asn,
# asOrganization, country, city, region.
_CF_META_URL = "https://speed.cloudflare.com/meta"


def _speedtest_download_mbps(num_bytes=25_000_000, timeout=20, connections=1):
	"""Baixa um bloco de tamanho conhecido e cronometra apenas o tempo de
	transferencia (sem contar o tempo de montagem da requisicao).

	connections>1: em vez de UMA conexao baixando o bloco inteiro, abre
	VARIAS conexoes TCP em PARALELO, cada uma baixando "num_bytes"
	INTEIRO (nao dividido entre elas - dividir um bloco pequeno demais
	entre varias conexoes terminava rapido demais pra sair do slow
	start mesmo rodando em paralelo, confirmado ao vivo numa conexao de
	1 Gbps) - importante em links rapidos: uma unica conexao TCP muitas
	vezes nao consegue saturar o link sozinha, porque o proprio TCP
	aumenta a janela de congestionamento aos poucos (slow start) - o
	link "e rapido o bastante" mas o protocolo ainda esta "acelerando"
	quando o bloco de teste ja acabou de chegar, subestimando a
	velocidade real. Multiplas conexoes em paralelo, cada uma com tempo
	suficiente pra sair do slow start, e a mesma tecnica que ferramentas
	profissionais de teste de velocidade usam pra medir link rapido com
	precisao.

	Devolve (mbps, erro): erro e None em caso de sucesso, ou uma string
	com o motivo real da falha (nome da excecao + mensagem) - sem isso,
	uma falha em blocos grandes ("Grande" = 100 MB) so aparecia como
	"falhou" sem nenhuma pista do porque."""
	if connections <= 1:
		try:
			req = urllib.request.Request(
				_CF_DOWN_URL.format(n=num_bytes),
				headers={"User-Agent": _CF_USER_AGENT, "Referer": _CF_REFERER},
			)
			total = 0
			start = time.perf_counter()
			with urllib.request.urlopen(req, timeout=timeout) as r:
				while True:
					chunk = r.read(65536)
					if not chunk:
						break
					total += len(chunk)
			elapsed = time.perf_counter() - start
			if elapsed <= 0 or total == 0:
				return None, "resposta vazia do servidor"
			if total < num_bytes:
				# Servidor entregou menos bytes do que foi pedido (conexao
				# cortada no meio) - a medicao com esse total parcial nao e
				# confiavel, melhor reportar como falha do que um numero
				# artificialmente baixo.
				return None, f"conexão interrompida ({total} de {num_bytes} bytes recebidos)"
			return (total * 8) / elapsed / 1_000_000, None
		except Exception as e:
			return None, f"{type(e).__name__}: {e}"

	# Modo paralelo: CADA conexao baixa "num_bytes" (nao o total dividido
	# entre elas) - um bloco pequeno por conexao terminaria rapido
	# demais pra sair do slow start mesmo rodando em paralelo (foi
	# exatamente o problema encontrado ao vivo: dividir 50 MB entre 4
	# conexoes dava so 12.5 MB cada, insuficiente). Mede o throughput
	# AGREGADO - soma dos bytes de todas as conexoes, dividido pelo
	# tempo do grupo inteiro (do inicio da primeira ate o fim da
	# ultima).
	por_conexao = num_bytes
	total_lock = threading.Lock()
	estado = {"total": 0, "erro": None, "algum_incompleto": False}
	def _uma():
		try:
			req = urllib.request.Request(
				_CF_DOWN_URL.format(n=por_conexao),
				headers={"User-Agent": _CF_USER_AGENT, "Referer": _CF_REFERER},
			)
			recebido = 0
			with urllib.request.urlopen(req, timeout=timeout) as r:
				while True:
					chunk = r.read(65536)
					if not chunk:
						break
					recebido += len(chunk)
			with total_lock:
				estado["total"] += recebido
				if recebido < por_conexao:
					estado["algum_incompleto"] = True
		except Exception as e:
			with total_lock:
				if not estado["erro"]:
					estado["erro"] = f"{type(e).__name__}: {e}"
	inicio = time.perf_counter()
	ts = [threading.Thread(target=_uma, daemon=True) for _i in range(connections)]
	for t in ts: t.start()
	for t in ts: t.join()
	elapsed = time.perf_counter() - inicio
	if elapsed <= 0 or estado["total"] == 0:
		return None, estado["erro"] or "resposta vazia do servidor"
	if estado["algum_incompleto"] and estado["total"] < por_conexao * connections * 0.9:
		return None, (estado["erro"] or "conexão interrompida em uma ou mais conexões paralelas")
	return (estado["total"] * 8) / elapsed / 1_000_000, None


def _speedtest_upload_mbps(num_bytes=5_000_000, timeout=20, connections=1):
	"""Envia um bloco de bytes irrelevantes (o conteudo nao importa, so o
	tamanho) via POST e cronometra o tempo ate a resposta do servidor.
	connections>1: mesma ideia do download em paralelo (ver
	_speedtest_download_mbps) - varias conexoes enviando ao mesmo tempo,
	throughput agregado, pra nao ficar limitado pelo slow start de uma
	unica conexao TCP em links rapidos. Devolve (mbps, erro) pelo mesmo
	motivo do download acima."""
	if connections <= 1:
		try:
			data = b"0" * num_bytes
			req = urllib.request.Request(
				_CF_UP_URL, data=data, method="POST",
				headers={
					"User-Agent": _CF_USER_AGENT,
					"Referer": _CF_REFERER,
					"Content-Type": "application/octet-stream",
				},
			)
			start = time.perf_counter()
			with urllib.request.urlopen(req, timeout=timeout) as r:
				r.read()
			elapsed = time.perf_counter() - start
			if elapsed <= 0:
				return None, "resposta vazia do servidor"
			return (num_bytes * 8) / elapsed / 1_000_000, None
		except Exception as e:
			return None, f"{type(e).__name__}: {e}"

	por_conexao = num_bytes
	dados_conexao = b"0" * por_conexao
	total_lock = threading.Lock()
	estado = {"ok_count": 0, "erro": None}
	def _uma():
		try:
			req = urllib.request.Request(
				_CF_UP_URL, data=dados_conexao, method="POST",
				headers={
					"User-Agent": _CF_USER_AGENT,
					"Referer": _CF_REFERER,
					"Content-Type": "application/octet-stream",
				},
			)
			with urllib.request.urlopen(req, timeout=timeout) as r:
				r.read()
			with total_lock:
				estado["ok_count"] += 1
		except Exception as e:
			with total_lock:
				if not estado["erro"]:
					estado["erro"] = f"{type(e).__name__}: {e}"
	inicio = time.perf_counter()
	ts = [threading.Thread(target=_uma, daemon=True) for _i in range(connections)]
	for t in ts: t.start()
	for t in ts: t.join()
	elapsed = time.perf_counter() - inicio
	if elapsed <= 0 or estado["ok_count"] == 0:
		return None, estado["erro"] or "resposta vazia do servidor"
	total_enviado = por_conexao * estado["ok_count"]
	return (total_enviado * 8) / elapsed / 1_000_000, None


def _speedtest_latency_ms(samples=3, timeout=10):
	# Mede a latencia ate o servidor do Cloudflare usado no teste de
	# velocidade, pedindo um "download" de 0 bytes (so o cabecalho de
	# resposta, sem corpo relevante) e cronometrando o tempo de ida e
	# volta. Faz algumas amostras e tira a media, do mesmo jeito que o
	# Ping Inteligente faz com o ICMP, para suavizar picos isolados.
	times = []
	for _ in range(samples):
		try:
			req = urllib.request.Request(
				_CF_DOWN_URL.format(n=0),
				headers={"User-Agent": _CF_USER_AGENT, "Referer": _CF_REFERER},
			)
			start = time.perf_counter()
			with urllib.request.urlopen(req, timeout=timeout) as r:
				r.read()
			times.append((time.perf_counter() - start) * 1000)
		except Exception:
			continue
	if not times:
		return None
	return round(sum(times) / len(times))


def speedtest_meta(timeout=10):
	"""Busca os metadados do teste de velocidade no endpoint oficial do
	Cloudflare (o mesmo que o site deles usa) - IP publico visto por
	eles, protocolo IP (IPv4/IPv6, inferido pela presenca de ":" no IP -
	o endpoint nao devolve isso como campo separado), e o codigo IATA do
	datacenter que atendeu a requisicao (ex.: "GRU" para Sao Paulo,
	"JFK" para Nova York) - da uma nocao de quao perto/longe o servidor
	usado no teste estava, o que ajuda a interpretar o resultado (um
	datacenter muito distante pode explicar uma latencia mais alta que o
	esperado). Devolve um dict SEMPRE (nunca None) - "error" vem None em
	caso de sucesso, ou o motivo real da falha (nome da excecao +
	mensagem) quando os campos vierem vazios, para dar uma pista do que
	deu errado em vez da linha so sumir silenciosamente da tela."""
	import json
	try:
		req = urllib.request.Request(_CF_META_URL, headers={
			"User-Agent": _CF_USER_AGENT, "Referer": _CF_REFERER, "Accept": "application/json",
		})
		with urllib.request.urlopen(req, timeout=timeout) as r:
			dados = json.loads(r.read().decode("utf-8", errors="replace"))
		ip = dados.get("clientIp")
		return {
			"ip": ip,
			"protocol": "IPv6" if (ip and ":" in ip) else ("IPv4" if ip else None),
			"colo": dados.get("colo"),
			"country": dados.get("country"),
			"city": dados.get("city"),
			"error": None,
		}
	except Exception as e:
		return {"ip": None, "protocol": None, "colo": None, "country": None, "city": None,
			"error": f"{type(e).__name__}: {e}"}


def _packet_loss_test(host, count=20, timeout_ms=1000):
	"""Testa perda de pacotes/jitter contra um host, priorizando o ICMP
	NATIVO (IcmpSendEcho, ver sysutils.py) - o ping.exe do Windows manda
	um pacote por segundo por padrao, SEM NENHUMA FORMA DOCUMENTADA de
	configurar esse intervalo, entao 20 pacotes via ping.exe levam quase
	20 segundos so nessa etapa. Via IcmpSendEcho, os 20 pacotes saem em
	sequencia sem essa pausa artificial - o tempo total fica limitado
	pela latencia real da rede (na pratica, pouco mais de 1 segundo numa
	conexao domestica comum), nao por uma decisao arbitraria do
	ping.exe. So cai pro ping.exe (mais lento, mas sempre disponivel) se
	a API nativa nao estiver disponivel nesse Windows.

	Devolve um dict no MESMO FORMATO de ping_parse() (avg/loss/recv/
	sent/jitter/std)."""
	if icmp_available():
		times = []
		recv = 0
		for _i in range(count):
			rtt = icmp_ping(host, timeout_ms=timeout_ms)
			if rtt is not None:
				times.append(rtt)
				recv += 1
		sent = count
		if recv == 0:
			return {"avg": None, "loss": 100, "recv": 0, "sent": sent}
		avg = round(sum(times) / recv)
		loss = round(((sent - recv) / sent) * 100)
		if recv >= 2:
			deltas = [abs(times[i] - times[i - 1]) for i in range(1, recv)]
			jitter = round(sum(deltas) / len(deltas), 1)
			std = round(statistics.stdev(times), 1)
		else:
			jitter = 0
			std = 0.0
		return {"avg": avg, "loss": loss, "recv": recv, "sent": sent, "jitter": jitter, "std": std}
	# Reserva: ping.exe por texto, mais lento (~1s por pacote) mas
	# funciona em qualquer Windows.
	return ping_parse(host, count=count, timeout=max(15, count * 2))


def internet_speed_test(download_bytes=25_000_000, upload_bytes=5_000_000,
		loss_host="1.1.1.1", loss_count=20, connections=1):
	"""Executa um teste de velocidade de internet real (latencia,
	download e upload), usando os endpoints publicos e gratuitos do
	Cloudflare. download_bytes/upload_bytes controlam o tamanho dos
	blocos transferidos - blocos maiores dao uma medicao mais estavel em
	conexoes rapidas (o TCP tem mais tempo pra sair do slow start), mas
	demoram mais e consomem mais dados.

	connections>1: usa VARIAS conexoes TCP em paralelo, cada uma
	transferindo download_bytes/upload_bytes INTEIRO (nao dividido entre
	elas - ver _speedtest_download_mbps para o motivo), medindo o
	throughput agregado. Recomendado pro preset "Grande", que ja e
	pensado pra conexoes rapidas - nesse caso o volume real transferido
	e "connections" vezes maior que download_bytes/upload_bytes.

	Alem de latencia/download/upload, tambem busca os metadados do
	Cloudflare (IP, protocolo IPv4/IPv6, datacenter) e roda um teste de
	PERDA DE PACOTES (ver _packet_loss_test acima) - a perda de pacotes e
	o indicador de ESTABILIDADE que a velocidade de download/upload
	sozinha nao mostra: uma conexao pode ser rapida e ainda assim
	instavel (ruim pra chamada de voz/video ou jogos online). Metadados
	e perda de pacotes rodam JUNTOS numa unica thread separada, em
	PARALELO com latencia/download/upload (que continuam na thread
	principal) - assim o tempo total do teste fica limitado pelo mais
	lento dos dois grupos, nao pela soma de tudo.

	Devolve um dict com "latency_ms" (inteiro ou None), "download" e
	"upload" ja formatados como texto legivel (ex.: "87 Mbps"),
	"download_error"/"upload_error" (motivo real da falha, ou None em
	caso de sucesso), "meta" (dict de speedtest_meta(), nunca None -
	confira "meta_erro" pra saber se falhou), "packet_loss_pct" (0-100
	ou None) e "jitter_ms"/"jitter_std_ms" (ou None) do teste de
	perda."""
	down_timeout = max(20, download_bytes // 1_000_000)
	up_timeout = max(20, upload_bytes // 1_000_000)

	extras = {}
	def _extras_worker():
		extras["meta"] = speedtest_meta()
		extras["loss"] = _packet_loss_test(loss_host, count=loss_count)
	extras_thread = threading.Thread(target=_extras_worker, daemon=True)
	extras_thread.start()

	latency_ms = _speedtest_latency_ms()
	down_mbps, down_err = _speedtest_download_mbps(
		num_bytes=download_bytes, timeout=down_timeout, connections=connections)
	up_mbps, up_err = _speedtest_upload_mbps(
		num_bytes=upload_bytes, timeout=up_timeout, connections=connections)

	# Da uma folga extra pros metadados+perda terminarem, caso
	# download+upload tenham ido mais rapido (conexao muito rapida com
	# blocos pequenos, por exemplo) - join() so bloqueia se realmente
	# precisar esperar, nao adiciona demora nenhuma no caso comum.
	extras_thread.join(timeout=30)
	meta = extras.get("meta") or {"ip": None, "protocol": None, "colo": None,
		"country": None, "city": None, "error": "tempo esgotado"}
	loss_dados = extras.get("loss")

	download = format_speed(int(down_mbps * 1_000_000)) if down_mbps else None
	upload = format_speed(int(up_mbps * 1_000_000)) if up_mbps else None
	return {
		"latency_ms": latency_ms, "download": download, "upload": upload,
		"download_mbps": down_mbps, "upload_mbps": up_mbps,
		"download_error": down_err, "upload_error": up_err,
		"meta": meta,
		"packet_loss_pct": loss_dados.get("loss") if loss_dados else None,
		"jitter_ms": loss_dados.get("jitter") if loss_dados else None,
		"jitter_std_ms": loss_dados.get("std") if loss_dados else None,
	}
