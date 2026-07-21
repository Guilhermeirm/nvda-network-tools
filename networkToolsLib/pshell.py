# -*- coding: utf-8 -*-
# Funcoes que dependem do PowerShell - isoladas neste modulo DE PROPOSITO,
# em vez de misturadas com netinfo.py. O resto do complemento usa so
# netsh/ipconfig/ping/tracert/etc nativos, que respondem quase
# instantaneamente porque ja fazem parte do processo do Windows. O
# PowerShell tem um custo de inicializacao de alguns segundos (precisa
# subir o runtime .NET) e pode estar bloqueado por politica de grupo em
# ambientes corporativos/escolares - por isso so entra aqui, em
# funcionalidades que genuinamente ganham algo que o netsh nao oferece
# (saida estruturada em JSON com nomes de campo sempre em ingles,
# independente do idioma do Windows; cmdlets sem equivalente nativo tao
# rico). Sempre com powershell_available() checado antes, e um aviso
# claro pro usuario quando nao estiver disponivel - nunca travando nem
# falhando silenciosamente.

import json
import subprocess

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Cache do resultado de powershell_available() - o teste em si custa os
# mesmos poucos segundos de inicializacao que estamos tentando poupar do
# usuario, entao so vale a pena pagar esse preco uma vez por sessao do
# NVDA, nao a cada vez que uma tela de diagnostico avancado for aberta.
_available_cache = None


def powershell_available():
	"""Testa (uma unica vez por sessao do NVDA - resultado fica em cache
	no modulo) se o PowerShell responde neste computador. False tanto se
	o executavel nao existe quanto se a politica de execucao/Group
	Policy bloqueia scripts - quem chama nao precisa (nem consegue)
	distinguir os dois casos, so sabe que essa funcionalidade nao vai
	funcionar aqui e deve avisar o usuario com clareza em vez de travar."""
	global _available_cache
	if _available_cache is not None:
		return _available_cache
	try:
		r = subprocess.run(
			["powershell", "-NoProfile", "-NonInteractive", "-Command", "1"],
			capture_output=True, timeout=15, creationflags=_CREATE_NO_WINDOW)
		_available_cache = (r.returncode == 0)
	except Exception:
		_available_cache = False
	return _available_cache


def _ps_escape(value):
	"""Escapa um valor pra uso seguro dentro de uma string de aspas
	simples do PowerShell (dobra cada aspa simples - convencao padrao do
	proprio PowerShell pra isso). Usado em todo valor vindo de fora
	(nome de interface, host digitado pelo usuario) antes de entrar num
	comando montado como texto."""
	return str(value).replace("'", "''")


def _run_json(command, timeout=20):
	"""Roda um comando/pipeline do PowerShell que termina em
	"| ConvertTo-Json -Depth 4" e devolve o resultado ja parseado (dict
	ou list). Devolve None se o PowerShell nao estiver disponivel, o
	comando falhar, ou a saida nao for JSON valido - quem chama trata
	None uniformemente como "essa informacao nao pode ser obtida agora",
	sem precisar saber o motivo exato (nao disponivel? sem permissao?
	adaptador nao encontrado? tudo vira a mesma orientacao pro usuario:
	tentar de novo ou usar as ferramentas nativas de sempre)."""
	if not powershell_available():
		return None
	try:
		r = subprocess.run(
			["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
			capture_output=True, timeout=timeout, creationflags=_CREATE_NO_WINDOW)
		if r.returncode != 0:
			return None
		# Decodificacao best-effort: PowerShell 5.1 x PowerShell 7+ variam
		# na codificacao padrao de stdout redirecionado (OEM x UTF-8,
		# dependendo da versao e da regiao do Windows) - UTF-8 com
		# fallback de substituicao cobre a imensa maioria dos casos sem
		# precisar detectar a versao instalada, ao custo de podermos
		# perder algum caractere acentuado raro num nome de interface,
		# em vez de quebrar a leitura inteira.
		out = r.stdout.decode("utf-8", errors="replace").strip()
		if not out:
			return None
		return json.loads(out)
	except Exception:
		return None


def adapter_rich_diagnostics(iface):
	"""Diagnostico avancado de UM adaptador via PowerShell, combinando
	tres cmdlets que juntos dao acesso a informacao que o netsh
	simplesmente nao expoe: MTU e metrica de rota (Get-NetIPInterface) e
	contadores de erro/descarte de pacotes (Get-NetAdapterStatistics),
	junto com a configuracao de IP basica (Get-NetIPConfiguration) para
	contexto. Devolve um dict ou None (PowerShell indisponivel, comando
	falhou, ou adaptador nao encontrado).

	DNSServers vem como LISTA (nao mais uma string ja unida) porque o
	Windows devolve os servidores DNS misturando IPv4 e IPv6 sem ordem
	semantica nenhuma (ex.: um link-local IPv6 aparecendo entre dois
	IPv4) - quem chama decide como ordenar/formatar pra exibicao (ver
	_psh_adapter em globalPlugins/networkTools.py)."""
	alias = _ps_escape(iface)
	cmd = (
		f"$cfg = Get-NetIPConfiguration -InterfaceAlias '{alias}' -ErrorAction SilentlyContinue; "
		f"$ipIf = Get-NetIPInterface -InterfaceAlias '{alias}' -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
		f"$stats = Get-NetAdapterStatistics -Name '{alias}' -ErrorAction SilentlyContinue; "
		"[PSCustomObject]@{"
		"InterfaceAlias=$cfg.InterfaceAlias;"
		"InterfaceDescription=$cfg.InterfaceDescription;"
		"IPv4Address=($cfg.IPv4Address.IPAddress -join ', ');"
		"IPv4Gateway=$cfg.IPv4DefaultGateway.NextHop;"
		"DNSServers=@($cfg.DNSServer.ServerAddresses);"
		"Mtu=$ipIf.NlMtu;"
		"InterfaceMetric=$ipIf.InterfaceMetric;"
		"ConnectionState=[string]$ipIf.ConnectionState;"
		"ReceivedBytes=$stats.ReceivedBytes;"
		"SentBytes=$stats.SentBytes;"
		"OutboundDiscardedPackets=$stats.OutboundDiscardedPackets;"
		"OutboundPacketErrors=$stats.OutboundPacketErrors;"
		"ReceivedDiscardedPackets=$stats.ReceivedDiscardedPackets;"
		"ReceivedPacketErrors=$stats.ReceivedPacketErrors"
		"} | ConvertTo-Json -Depth 4"
	)
	dados = _run_json(cmd)
	if not isinstance(dados, dict) or not dados.get("InterfaceAlias"):
		return None
	return dados

