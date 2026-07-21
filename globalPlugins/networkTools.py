# -*- coding: utf-8 -*-
# Network Tools para NVDA v9
# Atalho: NVDA+Shift+R
# Estrutura: PONTO DE ENTRADA unico em globalPlugins/ (sem subpasta,
# sem __init__.py aqui dentro) - padrao confirmado pelo Developer Guide
# oficial do NVDA 2026. Uma tentativa anterior de transformar isto num
# pacote (globalPlugins/networkTools/__init__.py) impediu o NVDA de
# carregar o complemento, entao esse formato de arquivo unico e
# obrigatorio para o ponto de entrada.
#
# A logica do complemento (coleta/interpretacao de dados de rede,
# dialogos wx, utilitarios de sistema) mora em networkToolsLib/, um
# pacote comum na RAIZ do addon (fora de globalPlugins/, entao o
# globalPluginHandler nunca o enxerga como candidato a plugin). As
# poucas linhas abaixo colocam a raiz do addon no sys.path para permitir
# o import normal - a mesma tecnica usada por outros complementos do
# NVDA que empacotam bibliotecas auxiliares proprias.
#
# Internacionalizacao: todos os textos exibidos ao usuario passam pela
# funcao _() (gettext), instalada por addonHandler.initTranslation().
# As traducoes ficam em locale/<idioma>/LC_MESSAGES/nvda.po (.mo).
# O idioma original do codigo (texto-fonte do catalogo) e portugues do
# Brasil; se o NVDA estiver em um idioma sem arquivo de traducao, o
# texto em portugues e usado como ultimo recurso (comportamento padrao
# do gettext).

import os
import sys

_ADDON_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ADDON_ROOT not in sys.path:
	sys.path.insert(0, _ADDON_ROOT)

import threading
import subprocess
import re
import json
import socket
import ipaddress
import time
import datetime
import statistics

import wx
import gui
import ui
import tones
import addonHandler
import globalPluginHandler
import config
import globalVars
from scriptHandler import script

addonHandler.initTranslation()
# A documentacao oficial da NVDA e explicita: initTranslation() deve ser
# chamado no topo de CADA modulo Python do addon que usa _() - nao uma
# vez so aqui. Os outros arquivos do addon (dialogs.py, netinfo.py,
# settingsPanel.py, sysutils.py) tem cada um a propria chamada; uma
# teoria anterior (capturar so uma copia do builtin em cada modulo) se
# provou incorreta na pratica, confirmado ao vivo pelo usuario num teste
# com a NVDA em espanhol - o painel de Configuracoes continuava
# aparecendo em portugues ate cada modulo passar a chamar
# initTranslation() por conta propria.

from networkToolsLib import regexes as rx
from networkToolsLib import sysutils as su
from networkToolsLib import netinfo as net
from networkToolsLib import firewall as fw
from networkToolsLib import dialogs as dlg
from networkToolsLib import pshell as psh
from networkToolsLib.settingsPanel import NetworkToolsSettingsPanel
from gui.settingsDialogs import NVDASettingsDialog

ADDON_SUMMARY = "Network Tools"

# ---------------------------------------------------------------------------
# Configuracao persistente (config.conf) - hoje so guarda a interface de
# rede escolhida manualmente pelo usuario (string vazia = automatico,
# comportamento de sempre). Registrado uma vez na importacao do modulo.
# ---------------------------------------------------------------------------
config.conf.spec["networkTools"] = {
	"selectedInterface":   "string(default='')",
	"monitorAutoStart":    "boolean(default=false)",
	"monitorInterval":     "integer(default=10,min=3,max=300)",
	"speedtestDefaultSize": "string(default='medium')",
	"speedtestConnections": "integer(default=4,min=1,max=8)",
	"pingDefaultCount":    "integer(default=4,min=1,max=1000)",
	"tracertDefaultHops":  "integer(default=30,min=1,max=64)",
	"dnsBestTimeout":      "integer(default=2,min=1,max=10)",
	"dnsBestSamples":      "integer(default=5,min=1,max=20)",
	"dnsBestFinalists":    "integer(default=8,min=1,max=20)",
	"dnsTestOneSamples":   "integer(default=10,min=1,max=50)",
	"dnsTestOneTimeout":   "integer(default=2,min=1,max=10)",
}


def _get_saved_iface():
	try:
		val = config.conf["networkTools"]["selectedInterface"]
	except Exception:
		return None
	return val or None


def _set_saved_iface(name):
	try:
		config.conf["networkTools"]["selectedInterface"] = name or ""
	except Exception:
		pass


# ---------------------------------------------------------------------------
# Menu principal
# ---------------------------------------------------------------------------
# Cada item e um par (id_estavel, rotulo_traduzido). O id_estavel nunca
# muda e e usado internamente para despachar a acao; o rotulo e o unico
# texto que aparece, na tela e por voz, e que varia conforme o idioma.

_MENU = [
	# translators: item de menu - consultar IP, mascara e gateway
	("ip_info",   _("Status de IP e Gateway")),
	# translators: item de menu - abre o submenu DNS (ver servidores atuais / aplicar DNS personalizado)
	("dns",       _("DNS (submenu)")),
	# translators: item de menu - abre o submenu com os diagnosticos de IPv6
	("ipv6",      _("IPv6 (submenu)")),
	# translators: item de menu - consultar dados e senha do Wi-Fi
	("wifi",      _("Informações e Senha Wi-Fi")),
	# translators: item de menu - descobrir o IP publico
	("pub_ip",    _("Descobrir IP Público")),
	# translators: item de menu - localizar geograficamente um IP
	("whois",     _("Localizar IP Externo")),
	# translators: item de menu - testar latencia com ping
	("ping",      _("Ping Inteligente")),
	# translators: item de menu - rastrear a rota ate um destino
	("tracert",   _("Rastreio de Rota")),
	# translators: item de menu - abre o submenu de varredura de dispositivos (varrer, e atualizar a base de fabricantes)
	("scan",      _("Varredura de Dispositivos (submenu)")),
	# translators: item de menu - testar velocidade de download e upload da internet
	("speedtest", _("Teste de Velocidade da Internet")),
	# translators: item de menu - definir IP estatico (requer admin)
	("static_ip", _("Definir IP Estático (Admin)")),
	# translators: item de menu - voltar a obter IP via DHCP (requer admin)
	("dhcp",      _("Voltar para IP Dinâmico (Admin)")),
	# translators: item de menu - abre o submenu de reparo e limpeza de rede
	("flush",     _("Reparo e Limpeza DNS (submenu)")),
	# translators: item de menu - abre o submenu com as ferramentas de firewall/portas
	("firewall",  _("Firewall (submenu)")),
	# translators: item de menu - abre o submenu do monitor de conexao (ligar/desligar, ver status)
	("monitor",   _("Monitor de Conexão (submenu)")),
	# translators: item de menu - MTU, metrica de rota e contadores de erro/descarte de pacotes do adaptador, via PowerShell (opcional, so se disponivel)
	("psh",       _("Diagnóstico Avançado do Adaptador (PowerShell)")),
]

# ---------------------------------------------------------------------------
# Submenu Firewall
# ---------------------------------------------------------------------------
# As acoes que MUDAM configuracao (criar regra, remover regra) exigem
# Administrador, no mesmo padrao ja usado em Definir IP Estatico/DHCP/
# Reparo de Rede. As de somente leitura (portas em escuta, regras ativas,
# status por perfil, teste local de porta) nao exigem.

_FIREWALL_MENU = [
	# translators: item do submenu de firewall - portas com algo escutando agora
	("fw_listen",     _("Portas Realmente Escutando Agora")),
	# translators: item do submenu de firewall - regras ativas de entrada e de saida
	("fw_rules",      _("Ver Regras de Firewall Ativas (Entrada e Saída)")),
	# translators: item do submenu de firewall - criar regra nova, de entrada ou saida (requer admin)
	("fw_create",     _("Criar Regra de Firewall (Admin)")),
	# translators: item do submenu de firewall - remover qualquer regra existente (requer admin)
	("fw_remove",     _("Remover Regra Existente (Admin)")),
	# translators: item do submenu de firewall - estado ligado/desligado por perfil de rede
	("fw_profiles",   _("Status do Firewall por Perfil")),
	# translators: item do submenu de firewall - testar localmente se uma porta esta escutando e liberada no firewall
	("fw_local_test", _("Testar Porta Localmente")),
]

# ---------------------------------------------------------------------------
# Submenu DNS
# ---------------------------------------------------------------------------
# "Aplicar DNS Personalizado" MUDA configuracao (requer Administrador, mesmo
# padrao ja usado em Definir IP Estatico/DHCP/Reparo de Rede/Firewall). "Ver
# Servidores DNS Atuais" e so consulta, nao exige.

_DNS_MENU = [
	# translators: item do submenu DNS - consultar os servidores DNS configurados agora
	("dns_view",  _("Ver Servidores DNS Atuais")),
	# translators: item do submenu DNS - testar varios servidores DNS publicos conhecidos e sugerir o mais rapido (a aplicacao, se confirmada, requer admin)
	("dns_best",  _("Buscar Melhor DNS")),
	# translators: item do submenu DNS - aplicar um servidor DNS escolhido pelo usuario, com teste previo (requer admin)
	("dns_apply", _("Aplicar DNS Personalizado (Admin)")),
	# translators: item do submenu DNS - gerenciar a lista inteira de servidores testados pela Busca de Melhor DNS (adicionar, editar, remover, inclusive os pre-configurados)
	("dns_manage", _("Gerenciar Servidores DNS")),
	# translators: item do submenu DNS - testar um unico servidor DNS avulso, sem afetar a lista gerenciada nem a configuracao do sistema
	("dns_test_one", _("Testar um Servidor DNS")),
]

# ---------------------------------------------------------------------------
# Submenu Reparo e Limpeza DNS
# ---------------------------------------------------------------------------
# Cada etapa que antes rodava sempre junta, sem escolha, agora tem seu
# proprio item - o usuario decide exatamente o que rodar. "Reparo
# Completo" continua existindo pra quem so quer o botao de sempre, e roda
# a mesma sequencia de 4 passos que o antigo item unico "(Admin)" ja
# rodava (flushdns + release + renew + winsock reset) - os dois itens
# novos (registrar DNS, resetar TCP/IP) ficam de fora do "Completo" de
# proposito, pra nao mudar o que esse botao ja fazia antes.
_FLUSH_MENU = [
	# translators: item do submenu de reparo - limpa o cache DNS local (requer admin)
	("flush_dns",      _("Limpar Cache DNS (Admin)")),
	# translators: item do submenu de reparo - reenvia o nome da maquina para o servidor DNS (requer admin)
	("flush_register", _("Registrar DNS Novamente (Admin)")),
	# translators: item do submenu de reparo - libera e renova o endereco IP via DHCP (requer admin)
	("flush_renew",    _("Renovar IP (Admin)")),
	# translators: item do submenu de reparo - reseta a pilha de sockets do Windows, geralmente exige reiniciar o PC (requer admin)
	("flush_winsock",  _("Resetar Pilha Winsock (Admin)")),
	# translators: item do submenu de reparo - reseta toda a pilha TCP/IP para os padroes de fabrica, geralmente exige reiniciar o PC (requer admin)
	("flush_tcpip",    _("Resetar Pilha TCP/IP (Admin)")),
	# translators: item do submenu de reparo - roda a sequencia completa de reparo de uma vez (cache DNS, IP, Winsock) (requer admin)
	("flush_all",      _("Reparo Completo (Admin)")),
]

# ---------------------------------------------------------------------------
# Diagnostico Avancado do Adaptador (PowerShell)
# ---------------------------------------------------------------------------
# Unico ponto do complemento que depende de PowerShell (ver
# networkToolsLib/pshell.py para o porque disso ficar isolado) - expoe
# informacao que o netsh genuinamente nao tem (MTU, metrica de rota,
# contadores de erro/descarte de pacotes por adaptador). Acao direta, sem
# submenu (o teste de porta TCP que morava aqui foi removido - virou uma
# opcao dentro do proprio Ping Inteligente, usando socket puro em vez de
# PowerShell, ja que fazia a mesma coisa por dois caminhos diferentes). So
# consulta, nenhuma acao aqui muda configuracao do sistema, entao nao
# exige Administrador - so exige o PowerShell estar disponivel, checado na
# hora (com aviso claro se nao estiver).

# ---------------------------------------------------------------------------
# Submenu IPv6
# ---------------------------------------------------------------------------
# O Windows mostra o endereco IPv6 configurado, mas nao diz se ele
# realmente funciona (chega na internet). Este submenu e so de consulta -
# nenhuma acao aqui muda configuracao do sistema, entao nada exige
# Administrador.

# ---------------------------------------------------------------------------
# Monitor de Conexao - intervalo de re-deteccao de rede
# ---------------------------------------------------------------------------
# De quanto em quanto tempo (em segundos, independente do intervalo de
# verificacao configuravel) o Monitor confere se o alvo/gateway ainda
# fazem sentido pra rede atual - ver _monitor_start(). Fixo (nao
# configuravel) porque e um detalhe de robustez interno, nao uma
# preferencia que o usuario precisaria ajustar.
_MONITOR_REDETECT_SECONDS = 60

# ---------------------------------------------------------------------------
# Teste de Velocidade da Internet - presets de tamanho
# ---------------------------------------------------------------------------
# Nao e um submenu de navegacao como os outros (DNS/IPv6/Firewall): e so
# uma escolha unica perguntada antes do teste rodar, entao nao tem
# dispatch proprio nem _return_menu dedicado. Cada item: (id, rotulo,
# bytes de download, bytes de upload).
# _SPEEDTEST_SIZES foi movida para net.speedtest_sizes() - fonte unica
# de verdade compartilhada com settingsPanel.py (ver comentario la e em
# netinfo.py para o motivo: as duas copias tinham dessincronizado na
# pratica antes dessa mudanca).

_IPV6_MENU = [
	# translators: item do submenu IPv6 - testa se o IPv6 realmente sai para a internet
	("ipv6_conn",  _("Teste de Conectividade IPv6")),
	# translators: item do submenu IPv6 - testa se o DNS resolve enderecos IPv6 (AAAA) e se da para conectar neles
	("ipv6_dns",   _("Teste de DNS IPv6")),
	# translators: item do submenu IPv6 - roda todos os testes de uma vez e da uma conclusao unica
	("ipv6_diag",  _("Diagnóstico IPv6 Completo")),
]

# ---------------------------------------------------------------------------
# Submenu Varredura de Dispositivos
# ---------------------------------------------------------------------------
# Dois itens relacionados: a varredura em si (sempre offline, so rede
# local), e a atualizacao opcional da base completa de fabricantes por
# MAC (usa internet, so quando pedido - ver _update_oui_database). Ficam
# juntos porque a segunda so existe pra enriquecer o resultado da
# primeira.
_SCAN_MENU = [
	# translators: item do submenu de varredura - varre a rede local por dispositivos (ping+ARP+portas)
	("scan_run",   _("Varredura de Dispositivos")),
	# translators: item do submenu de varredura - baixa a base completa de fabricantes por MAC da IEEE (opcional, usa internet, so quando pedido)
	("oui_update", _("Atualizar Base de Fabricantes Completa")),
]

# ---------------------------------------------------------------------------
# Plugin Global
# ---------------------------------------------------------------------------


class GlobalPlugin(globalPluginHandler.GlobalPlugin):

	scriptCategory = ADDON_SUMMARY

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._mon = None
		self._mon_on = False
		# Numero de sessao do Monitor - incrementado toda vez que liga
		# (ver _monitor_start). A thread "vigia" de mudanca de rede (ver
		# NotifyAddrChange em sysutils.py) fica bloqueada esperando um
		# evento do Windows que pode demorar a acontecer; se o usuario
		# desligar e ligar o Monitor de novo nesse meio tempo, uma vigia
		# "orfa" da sessao anterior poderia acordar depois e mexer no
		# estado da sessao NOVA por engano. Cada vigia guarda consigo o
		# numero da sessao em que nasceu e confere se ainda bate antes de
		# fazer qualquer coisa - se nao bate, e uma vigia orfa, e so sai
		# sem efeito nenhum.
		self._mon_generation = 0
		# Estado estendido do monitor - preenchido quando ligado (ver
		# _monitor_toggle), consultado por _monitor_status sem precisar
		# esperar o proximo evento de queda/retomada.
		self._mon_start_ts = None
		# Estatisticas SEPARADAS por rede (SSID do Wi-Fi, ou MAC do
		# gateway para Ethernet/outros - ver _resolve_network_identity)
		# - cada valor e um dict com target/gateway/iface_name/
		# latencies/gw_latencies/drop_count/down_since/
		# total_down_seconds/total_checks/last_latency_ms/
		# last_gw_latency_ms/last_scope/last_active_ts. Trocar de rede
		# NAO perde o historico da rede anterior - so passa a acumular
		# num dict diferente; voltar a uma rede ja visitada nesta sessao
		# CONTINUA de onde parou, sem perder nada (reiniciar a NVDA e a
		# unica coisa que zera tudo, ja que isto nunca e salvo em
		# disco - decisao deliberada, pra nao precisar lidar com
		# retencao/privacidade de guardar nomes de rede permanentemente).
		self._mon_networks = {}
		self._mon_current_network_id = None
		# Para qual menu voltar depois de uma acao terminar (resultado,
		# mensagem, ou cancelamento no meio do caminho). _dispatch e
		# _dispatch_firewall atualizam isto ANTES de chamar o metodo da
		# acao escolhida - assim _back()/_say()/_show() sempre devolvem o
		# usuario ao menu de onde ele veio (principal ou Firewall), em vez
		# de sempre pular para o menu principal.
		self._return_menu = self._show_menu

		NVDASettingsDialog.categoryClasses.append(NetworkToolsSettingsPanel)
		if config.conf["networkTools"]["monitorAutoStart"]:
			self._monitor_start(announce=False)

	# Atalho NVDA+Shift+R - padrao exato do Developer Guide oficial
	@script(
		# translators: descricao do comando no dialogo de gestos de entrada do NVDA
		description=_("Abre o menu do Network Tools"),
		gesture="kb:NVDA+shift+r",
	)
	def script_openMenu(self, gesture):
		wx.CallAfter(self._show_menu)

	@script(
		# translators: descricao do comando no dialogo de gestos de entrada do NVDA
		description=_("Fala o estado atual da conexão de internet"),
		gesture="kb:NVDA+shift+c",
	)
	def script_connectionStatus(self, gesture):
		wx.CallAfter(self._speak_connection_status)

	def _speak_connection_status(self):
		"""Atalho pensado pra situacao em que o usuario esta lendo algo
		(ou digitando) bem na hora em que a conexao cai - o aviso falado
		do Monitor pode passar despercebido (ou ser cortado por uma tecla
		pressionada no momento errado). Isto da um jeito de perguntar "como
		esta minha conexao AGORA" a qualquer momento, sem precisar abrir
		menu nenhum.

		Depende do Monitor estar ligado - a resposta usa o que ELE ja sabe
		(conectado/perdida + latencia MEDIA do adaptador local e de
		DNS/internet, separadas), entao sem o Monitor rodando nao ha nada
		acumulado pra responder. Nao faz uma checagem avulsa nem liga o
		Monitor sozinho - so avisa que esta desativado, e quem quiser usar
		o atalho liga o Monitor primeiro pelo submenu."""
		if not self._mon_on:
			ui.message(_("Monitor desativado."))
			return
		if not self._mon_current_network_id:
			ui.message(_("Monitor ativo, ainda aguardando a primeira verificação."))
			return
		rede = self._mon_networks[self._mon_current_network_id]
		agora = time.time()
		if rede["down_since"]:
			msg = _("Conexão de rede perdida (há {dur}).").format(
				dur=self._fmt_duration(agora - rede["down_since"]))
			if rede["last_scope"] == "local":
				msg += " " + _("O roteador também não está respondendo.")
		elif rede["latencies"]:
			media = sum(rede["latencies"]) / len(rede["latencies"])
			if rede["gw_latencies"]:
				gw_media = sum(rede["gw_latencies"]) / len(rede["gw_latencies"])
				nome_iface = rede["iface_name"] or _("adaptador de rede")
				msg = _(
					"Conectado. Latência média de {iface}: {gw} ms. "
					"Latência média do DNS/internet: {dns} ms."
				).format(iface=nome_iface, gw=round(gw_media), dns=round(media))
			else:
				msg = _("Conectado. Latência média do DNS/internet: {ms} ms.").format(ms=round(media))
		else:
			msg = _("Monitor ativo, ainda aguardando a primeira verificação.")
		ui.message(msg)

	def _show_menu(self):
		# net.list_interfaces() dispara um netsh (subprocesso) - antes,
		# _build_iface_tabs() e _menu_items_for_iface() chamavam isso cada
		# um por conta propria, rodando o MESMO comando duas vezes seguidas
		# de forma sincrona (bloqueando a tela) toda vez que o menu abria
		# com a aba "Automatico" selecionada, que e o caso mais comum.
		# Buscar uma vez so e reaproveitar nos dois corta essa espera pela
		# metade, sem mudar nada do comportamento.
		interfaces = net.list_interfaces()
		iface_tabs, initial_idx = self._build_iface_tabs(interfaces)
		initial_iface = iface_tabs[initial_idx][0] if iface_tabs else None
		menu_items = self._menu_items_for_iface(initial_iface, interfaces)
		gui.mainFrame.prePopup()
		with dlg.MenuDialog(gui.mainFrame, ADDON_SUMMARY, menu_items,
				iface_tabs=iface_tabs, initial_tab_index=initial_idx,
				on_iface_change=self._on_iface_tab_changed) as d:
			ret = d.ShowModal()
			chosen = d.chosen
		gui.mainFrame.postPopup()
		if ret == wx.ID_OK and chosen:
			wx.CallAfter(self._dispatch, chosen)

	@staticmethod
	def _iface_is_wifi(name):
		"""True quando o NOME do adaptador indica claramente um radio
		Wi-Fi (mesmo criterio locale-independente ja usado no restante do
		complemento, via RX_WIFI_IFACE_NAME)."""
		return bool(name) and bool(rx.RX_WIFI_IFACE_NAME.search(name))

	def _menu_items_for_iface(self, iface_name, interfaces=None):
		"""Filtra o item "Informacoes e Senha Wi-Fi" fora da lista de
		acoes quando ele claramente nao se aplica - nao faz sentido
		oferece-lo com uma interface Ethernet selecionada. Todo o resto
		do menu principal e universal e continua aparecendo sempre; so
		este item e tratado como especifico de interface.

		iface_name None = aba "Automatico": aqui nao ha uma interface
		especifica selecionada, entao o item so aparece se um adaptador
		Wi-Fi estiver de fato CONECTADO agora - senao o usuario cairia
		direto num "nenhuma rede Wi-Fi" sem necessidade.

		interfaces: lista ja obtida via net.list_interfaces(), pra quem
		chama (_show_menu) reaproveitar em vez de rodar o netsh nesse
		caso de novo. Se None, busca por conta propria - usado por quem
		chama isso fora do caminho de abertura do menu (troca de aba
		dentro do dialogo ja aberto), onde nao ha lista pronta pra
		reaproveitar mesmo."""
		if iface_name is None:
			if interfaces is None:
				interfaces = net.list_interfaces()
			show_wifi = any(
				self._iface_is_wifi(i["name"]) and i["connected"]
				for i in interfaces
			)
		else:
			show_wifi = self._iface_is_wifi(iface_name)
		if show_wifi:
			return _MENU
		return [item for item in _MENU if item[0] != "wifi"]

	def _build_iface_tabs(self, interfaces):
		"""Monta a lista de abas de interface (id, rotulo) para o menu
		principal: "Automatico" primeiro, depois uma aba por adaptador
		detectado. Devolve tambem o indice inicial que deve ficar
		selecionado, de acordo com a escolha salva atualmente.

		interfaces: lista ja obtida via net.list_interfaces() por quem
		chama (_show_menu) - ver comentario em _menu_items_for_iface."""
		saved = _get_saved_iface()
		# translators: rotulo curto da primeira aba de interface (modo automatico) - aparece dentro de uma faixa de abas, entao precisa ser curto
		tabs = [(None, _("Automático"))]
		initial_idx = 0
		for i, iface in enumerate(interfaces, start=1):
			tabs.append((iface["name"], iface["name"]))
			if saved and iface["name"] == saved:
				initial_idx = i
		return tabs, initial_idx

	def _on_iface_tab_changed(self, iface_name):
		"""Chamado na hora em que o usuario troca de aba de interface no
		menu principal (Ctrl+Tab ou setas) - aplica a escolha na hora, sem
		precisar confirmar nada, avisa por voz qual interface passou a
		valer, e devolve a lista de acoes recalculada para esta interface
		(hoje isto so muda a presenca do item de Wi-Fi) para que o
		MenuDialog atualize a lista de acoes visivel."""
		_set_saved_iface(iface_name)
		if iface_name:
			ui.message(_("Interface de rede definida como {name}.").format(name=iface_name))
		else:
			ui.message(_("Interface de rede definida como automática."))
		return self._menu_items_for_iface(iface_name)

	def _resolve_iface(self):
		"""Devolve a interface a usar: a escolhida manualmente pelo
		usuario, se ela ainda existir na maquina; senao None, que faz
		cada chamador cair de volta no active_iface() automatico de
		sempre. Se a interface salva sumiu (adaptador USB removido, VPN
		desligada etc.), limpa a escolha em vez de insistir num nome que
		nao existe mais."""
		saved = _get_saved_iface()
		if not saved:
			return None
		names = {i["name"] for i in net.list_interfaces()}
		if saved in names:
			return saved
		_set_saved_iface(None)
		return None

	def _resolve_network_identity(self, iface_name, gateway_ip):
		"""Identifica QUAL rede um adaptador esta conectado agora - usado
		pelo Monitor de Conexao como chave nas estatisticas por rede (ver
		_monitor_start), pra separar o historico de cada rede visitada
		durante a sessao em vez de misturar tudo numa media so.

		Wi-Fi usa o SSID (nome da rede) - dois roteadores diferentes tem
		SSIDs diferentes, mesmo que por acaso usem a mesma faixa de IP.
		Qualquer outra coisa (Ethernet, adaptador virtual etc., que nao
		tem SSID nenhum) usa o MAC do gateway - tambem um identificador
		fisico estavel, que nao muda so porque o IP do roteador mudou via
		DHCP.

		Devolve (chave, rotulo_de_exibicao) - nunca falha: se nada for
		identificavel (ex.: SendARP e a consulta de SSID falharam as
		duas), cai de volta pro proprio nome da interface, que sempre
		existe."""
		ssid = net.wifi_ssid_for_iface(iface_name) if iface_name else None
		if ssid:
			return f"wifi:{ssid}", ssid
		mac = net.gateway_mac(gateway_ip) if gateway_ip else None
		if mac:
			# translators: rotulo de uma rede sem SSID (Ethernet ou outro adaptador), identificada pelo MAC do roteador - {iface} e o nome do adaptador (ex. "Ethernet"), {mac} e o endereco MAC do gateway
			return f"mac:{mac}", _("Ethernet ({iface}, roteador {mac})").format(iface=iface_name, mac=mac)
		chave = f"iface:{iface_name}" if iface_name else "iface:desconhecida"
		return chave, (iface_name or _("rede desconhecida"))

	def _get_or_create_network(self, net_id, label, target, gateway, iface_name):
		"""Busca (ou cria, na primeira vez) a entrada de estatisticas de
		uma rede especifica dentro de self._mon_networks - ver o
		comentario completo la (no __init__) para a estrutura de cada
		entrada. Voltar a uma rede ja visitada nesta sessao do Monitor
		REAPROVEITA a entrada existente (soma ao que ja tinha, nao
		reinicia do zero) - so atualiza target/gateway/iface_name, que
		podem ter mudado um pouco mesmo sendo "a mesma rede" (ex.: o
		gateway trocou de IP via DHCP, mas o MAC dele - a chave usada -
		continua o mesmo)."""
		rede = self._mon_networks.get(net_id)
		if rede is None:
			rede = {
				"label": label,
				"target": target,
				"gateway": gateway,
				"iface_name": iface_name,
				"latencies": [],
				"gw_latencies": [],
				"drop_count": 0,
				"down_since": None,
				"total_down_seconds": 0.0,
				"total_checks": 0,
				"last_latency_ms": None,
				"last_gw_latency_ms": None,
				"last_scope": None,
				"last_check_ts": None,
				"first_seen_ts": time.time(),
			}
			self._mon_networks[net_id] = rede
		else:
			rede["target"] = target
			rede["gateway"] = gateway
			rede["iface_name"] = iface_name
		return rede

	def _dispatch(self, choice):
		self._return_menu = self._show_menu
		{
			"ip_info":   self._ip_info,
			"dns":       self._show_dns_menu,
			"ipv6":      self._show_ipv6_menu,
			"wifi":      self._wifi,
			"pub_ip":    self._pub_ip,
			"whois":     self._whois,
			"ping":      self._ping,
			"tracert":   self._tracert,
			"scan":      self._show_scan_menu,
			"speedtest": self._speedtest,
			"static_ip": self._static_ip,
			"dhcp":      self._dhcp,
			"flush":     self._show_flush_menu,
			"firewall":  self._show_firewall_menu,
			"monitor":   self._show_monitor_menu,
			"psh":       self._psh_adapter,
		}.get(choice, lambda: None)()

	def _show_dns_menu(self):
		gui.mainFrame.prePopup()
		with dlg.MenuDialog(gui.mainFrame, _("DNS"), _DNS_MENU) as d:
			ret = d.ShowModal()
			chosen = d.chosen
		gui.mainFrame.postPopup()
		if ret == wx.ID_OK and chosen:
			wx.CallAfter(self._dispatch_dns, chosen)
		else:
			# Cancelar/Escape aqui deve voltar ao menu PRINCIPAL, nao so
			# fechar tudo - sem isso, sair de um submenu sem escolher nada
			# "saia do complemento" por completo, exigindo acionar o
			# atalho de novo (confirmado ao vivo pelo usuario).
			wx.CallAfter(self._show_menu)

	def _dispatch_dns(self, choice):
		self._return_menu = self._show_dns_menu
		{
			"dns_view":  self._dns_view,
			"dns_best":  self._dns_best,
			"dns_apply": self._dns_apply,
			"dns_manage": self._dns_manage,
			"dns_test_one": self._dns_test_one,
		}.get(choice, lambda: None)()

	def _show_flush_menu(self):
		gui.mainFrame.prePopup()
		with dlg.MenuDialog(gui.mainFrame, _("Reparo e Limpeza DNS"), _FLUSH_MENU) as d:
			ret = d.ShowModal()
			chosen = d.chosen
		gui.mainFrame.postPopup()
		if ret == wx.ID_OK and chosen:
			wx.CallAfter(self._dispatch_flush, chosen)
		else:
			wx.CallAfter(self._show_menu)

	def _dispatch_flush(self, choice):
		self._return_menu = self._show_flush_menu
		{
			"flush_dns":      self._flush_dns,
			"flush_register": self._flush_register,
			"flush_renew":    self._flush_renew,
			"flush_winsock":  self._flush_winsock,
			"flush_tcpip":    self._flush_tcpip,
			"flush_all":      self._flush_all,
		}.get(choice, lambda: None)()

	def _monitor_toggle_label(self):
		"""Rotulo dinamico do item que liga/desliga o monitor - calculado
		TODA VEZ que o submenu e aberto (_show_monitor_menu chama isto de
		novo a cada abertura), entao sempre reflete o estado atual sem
		precisar entrar no item pra descobrir."""
		if self._mon_on:
			# translators: rotulo do item quando o monitor de conexao ja esta ativo
			return _("Desligar Monitor de Conexão (está ativo)")
		# translators: rotulo do item quando o monitor de conexao esta desligado
		return _("Ligar Monitor de Conexão (está desligado)")

	def _show_monitor_menu(self):
		itens = [
			("monitor_toggle", self._monitor_toggle_label()),
			# translators: item do submenu de Monitor - consulta o status atual sem ligar nem desligar nada
			("monitor_status", _("Ver Status do Monitor")),
		]
		gui.mainFrame.prePopup()
		with dlg.MenuDialog(gui.mainFrame, _("Monitor de Conexão"), itens) as d:
			ret = d.ShowModal()
			chosen = d.chosen
		gui.mainFrame.postPopup()
		if ret == wx.ID_OK and chosen:
			wx.CallAfter(self._dispatch_monitor, chosen)
		else:
			wx.CallAfter(self._show_menu)

	def _dispatch_monitor(self, choice):
		self._return_menu = self._show_monitor_menu
		{
			"monitor_toggle": self._monitor_toggle,
			"monitor_status": self._monitor_status,
		}.get(choice, lambda: None)()

	def _show_ipv6_menu(self):
		gui.mainFrame.prePopup()
		with dlg.MenuDialog(gui.mainFrame, _("IPv6"), _IPV6_MENU) as d:
			ret = d.ShowModal()
			chosen = d.chosen
		gui.mainFrame.postPopup()
		if ret == wx.ID_OK and chosen:
			wx.CallAfter(self._dispatch_ipv6, chosen)
		else:
			wx.CallAfter(self._show_menu)

	def _dispatch_ipv6(self, choice):
		self._return_menu = self._show_ipv6_menu
		{
			"ipv6_conn":  self._ipv6_conn,
			"ipv6_dns":   self._ipv6_dns,
			"ipv6_diag":  self._ipv6_diag,
		}.get(choice, lambda: None)()

	def _show_scan_menu(self):
		gui.mainFrame.prePopup()
		with dlg.MenuDialog(gui.mainFrame, _("Varredura de Dispositivos"), _SCAN_MENU) as d:
			ret = d.ShowModal()
			chosen = d.chosen
		gui.mainFrame.postPopup()
		if ret == wx.ID_OK and chosen:
			wx.CallAfter(self._dispatch_scan, chosen)
		else:
			wx.CallAfter(self._show_menu)

	def _dispatch_scan(self, choice):
		self._return_menu = self._show_scan_menu
		{
			"scan_run":   self._scan,
			"oui_update": self._update_oui_database,
		}.get(choice, lambda: None)()

	def _show_firewall_menu(self):
		gui.mainFrame.prePopup()
		with dlg.MenuDialog(gui.mainFrame, _("Firewall"), _FIREWALL_MENU) as d:
			ret = d.ShowModal()
			chosen = d.chosen
		gui.mainFrame.postPopup()
		if ret == wx.ID_OK and chosen:
			wx.CallAfter(self._dispatch_firewall, chosen)
		else:
			wx.CallAfter(self._show_menu)

	def _dispatch_firewall(self, choice):
		self._return_menu = self._show_firewall_menu
		{
			"fw_listen":     self._fw_listen,
			"fw_rules":      self._fw_rules,
			"fw_create":     self._fw_create,
			"fw_remove":     self._fw_remove,
			"fw_profiles":   self._fw_profiles,
			"fw_local_test": self._fw_local_test,
		}.get(choice, lambda: None)()

	# --- Auxiliares de UI (unico lugar que fala com wx/ui/gui) ---

	def _back(self):
		"""Volta para o menu de onde a acao atual foi disparada (principal
		ou Firewall) - ver comentario de self._return_menu em __init__."""
		self._return_menu()

	def _say(self, txt):
		# So fala a mensagem, sem reabrir o menu em seguida. Foi exatamente
		# essa combinacao (falar + trocar o foco pro menu logo depois) que
		# cortava a fala no meio - a troca de foco interrompe a fala do
		# NVDA. Sem reabrir nada automaticamente, nao sobra nenhuma acao
		# do addon que possa cortar essa fala. Efeito colateral aceito de
		# proposito: o menu NAO volta sozinho depois disto - e preciso
		# acionar o addon de novo (NVDA+Shift+R) para continuar usando.
		ui.message(txt)

	def _show(self, title, txt):
		ui.message(txt.split("\n")[0])
		gui.mainFrame.prePopup()
		with dlg.ResultDialog(gui.mainFrame, title, txt) as d:
			d.ShowModal()
		gui.mainFrame.postPopup()
		self._back()

	def _show_tabs(self, title, tabs):
		"""Como _show, mas em abas separadas (dlg.TabbedResultDialog) - usado
		quando o resultado tem secoes bem distintas (ex.: Entrada/Saida) que
		ficariam dificeis de navegar como um unico texto longo."""
		gui.mainFrame.prePopup()
		with dlg.TabbedResultDialog(gui.mainFrame, title, tabs) as d:
			d.ShowModal()
		gui.mainFrame.postPopup()
		self._back()

	def _ask(self, title, label, default=""):
		gui.mainFrame.prePopup()
		with dlg.AskDialog(gui.mainFrame, title, label, default) as d:
			ret = d.ShowModal()
			val = d.value if ret == wx.ID_OK else None
		gui.mainFrame.postPopup()
		return val

	def _ask_target_param(self, title, target_label, target_default, param_label, param2_label=None):
		"""Pede um alvo obrigatorio (com valor padrao pre-preenchido, como
		os outros dialogos ja fazem) mais um ou dois parametros opcionais
		(campos vazios de proposito). Devolve sempre uma tripla (alvo,
		texto_do_parametro, texto_do_parametro2) - os textos vem crus, sem
		validar como numero, porque cada chamador sabe qual e o proprio
		padrao e os proprios limites razoaveis. param2_texto vem "" quando
		param2_label nao foi pedido (o dialogo nem mostra esse campo nesse
		caso). Devolve (None, None, None) se o usuario cancelar."""
		gui.mainFrame.prePopup()
		with dlg.TargetParamDialog(gui.mainFrame, title, target_label, target_default, param_label, param2_label) as d:
			ret = d.ShowModal()
			if ret == wx.ID_OK:
				target, param, param2 = d.target, d.param, d.param2
			else:
				target, param, param2 = None, None, None
		gui.mainFrame.postPopup()
		return target, param, param2

	@staticmethod
	def _parse_int_or_default(text, default, min_v, max_v):
		"""Converte o texto digitado num parametro numerico opcional (como
		numero de pacotes de ping ou limite de saltos). Em branco,
		invalido, ou fora da faixa razoavel -> usa o padrao normal em vez
		de travar a acao ou aceitar um valor absurdo."""
		text = (text or "").strip()
		if not text:
			return default
		try:
			n = int(text)
		except ValueError:
			return default
		if n < min_v or n > max_v:
			return default
		return n

	def _no_admin(self):
		ui.message(_("Requer NVDA rodando como Administrador."))
		self._back()
		return False

	# --- Modulo A ---

	def _ip_block_text(self, d, host):
		"""Formata os dados de UM adaptador (o dict que get_ip_config()/
		all_ip_configs() devolvem) como o texto mostrado em Status de IP -
		extraido a parte para ser reaproveitado tanto na visao unica
		quanto em cada aba, quando ha mais de uma interface ativa."""
		iface = d.get("iface")
		mac = net.get_mac_address(iface) if iface else None
		ipv6 = net.get_ipv6(iface) if iface else None
		speed = net.get_link_speed(iface) if iface else None
		if d.get("dhcp") is True:
			modo = _("Dinâmico (DHCP)")
		elif d.get("dhcp") is False:
			modo = _("Fixo (Estático)")
		else:
			modo = _("não detectado")
		return su.fmt(
			(_("Nome do computador"), host),
			(_("Interface"),     iface),
			(_("Endereço IPv4"), d["ipv4"]),
			(_("Máscara"),       d["mask"] or _("não encontrada")),
			(_("Gateway"),       d["gateway"] or _("não encontrado")),
			(_("Modo de IP"),    modo),
			(_("Endereço MAC"),  mac or _("não encontrado")),
			(_("Endereço IPv6"), ipv6 or _("não encontrado")),
			(_("Velocidade do adaptador de rede"), speed or _("não detectada")),
		)

	def _ip_info(self):
		ui.message(_("Consultando IP, aguarde."))
		def worker():
			host = net.hostname()
			resolved = self._resolve_iface()
			if not resolved:
				# Modo automatico: se houver mais de uma interface com IP
				# valido ao mesmo tempo (ex.: Ethernet conectado e Wi-Fi
				# ativo simultaneamente), mostra todas em abas em vez de
				# escolher uma so - nesse caso ha ambiguidade real, e ver
				# tudo de uma vez e mais util do que adivinhar qual
				# interessa. Com uma interface so (o caso comum), segue o
				# fluxo normal abaixo, sem abas.
				all_configs = net.all_ip_configs()
				if len(all_configs) > 1:
					tabs = [(d.get("iface") or _("Interface"), self._ip_block_text(d, host))
						for d in all_configs]
					wx.CallAfter(self._show_tabs, _("Status de IP e Gateway"), tabs)
					return
			d = net.get_ip_config(resolved)
			if d and d.get("ipv4"):
				wx.CallAfter(self._show, _("Status de IP e Gateway"), self._ip_block_text(d, host))
				return
			if resolved:
				# Interface escolhida manualmente nao tem IP valido agora.
				# NAO cai na reserva de ipconfig abaixo (que nao sabe
				# filtrar por interface e acabaria rotulando dados de OUTRO
				# adaptador como se fossem desta) - avisa claramente em vez
				# de misturar adaptadores diferentes.
				wx.CallAfter(self._say, _(
					"A interface selecionada ({iface}) não tem endereço IP configurado no momento."
				).format(iface=resolved))
				return
			# Reserva (so em modo automatico, sem interface escolhida
			# manualmente): ipconfig por texto (so reconhece ES/EN/PT)
			ok, out = su.run(["ipconfig", "/all"])
			if not ok:
				wx.CallAfter(self._say, _("Erro ao obter IP."))
				return
			d = net.parse_ipcfg(out)
			iface = net.active_iface()
			mac = net.get_mac_address(iface) if iface else None
			ipv6 = net.get_ipv6(iface) if iface else None
			speed = net.get_link_speed(iface) if iface else None
			wx.CallAfter(self._show, _("Status de IP e Gateway"), su.fmt(
				(_("Nome do computador"), host),
				(_("Interface"),     iface),
				(_("Endereço IPv4"), d["ipv4"] or _("não encontrado")),
				(_("Máscara"),       d["mask"] or _("não encontrada")),
				(_("Gateway"),       d["gateway"] or _("não encontrado")),
				(_("Endereço MAC"),  mac or _("não encontrado")),
				(_("Endereço IPv6"), ipv6 or _("não encontrado")),
				(_("Velocidade do adaptador de rede"), speed or _("não detectada")),
			))
		su.run_bg(worker)

	def _dns_view(self):
		ui.message(_("Consultando DNS, aguarde."))
		def worker():
			resolved = self._resolve_iface()
			d = net.get_ip_config(resolved)
			dns = d.get("dns") if d else None
			if not dns and resolved:
				# Interface escolhida manualmente nao tem IP valido agora -
				# NAO cai na reserva de ipconfig abaixo (que nao filtra por
				# interface e acabaria mostrando o DNS de OUTRO adaptador
				# como se fosse deste).
				wx.CallAfter(self._say, _(
					"A interface selecionada ({iface}) não tem endereço IP configurado no momento."
				).format(iface=resolved))
				return
			if not dns:
				# Reserva (so em modo automatico): ipconfig por texto (so reconhece ES/EN/PT)
				ok, out = su.run(["ipconfig", "/all"])
				if not ok:
					wx.CallAfter(self._say, _("Erro ao obter DNS."))
					return
				dns = net.parse_ipcfg(out)["dns"]
			if not dns:
				wx.CallAfter(self._say, _("Nenhum DNS encontrado."))
				return
			blocks = [_("Servidores DNS:")]
			for i, ip in enumerate(dns):
				latency = net.measure_dns_latency(ip)
				provider = net.identify_dns_provider(ip)
				# translators: rotulo de latencia dentro do bloco de cada servidor DNS
				latency_txt = _("{ms} ms").format(ms=latency) if latency is not None else _("sem resposta")
				block = su.fmt(
					(_("Servidor {n}").format(n=i + 1), ip),
					(_("Latência"), latency_txt),
					(_("Provedor"), provider or _("não identificado")),
				)
				blocks.append(block)
			txt = "\n\n".join(blocks)
			wx.CallAfter(self._show, _("Servidores DNS"), txt)
		su.run_bg(worker)

	def _dns_best(self):
		amostras = config.conf["networkTools"]["dnsBestSamples"]
		# translators: mensagem de progresso da busca em duas fases pelo DNS mais rapido e estavel - {n} mostra o numero de consultas por servidor configurado em Preferencias > Configuracoes, para confirmar visivelmente que o valor configurado esta sendo usado de verdade
		ui.message(_(
			"Buscando o DNS mais rápido e estável entre os servidores da "
			"sua lista ({n} consultas por servidor), aguarde."
		).format(n=amostras))
		def worker():
			resolved = self._resolve_iface()
			d = net.get_ip_config(resolved)
			dns_atual = d.get("dns") if d else None
			if not dns_atual and resolved:
				wx.CallAfter(self._say, _(
					"A interface selecionada ({iface}) não tem endereço IP configurado no momento."
				).format(iface=resolved))
				return
			if not dns_atual:
				# Reserva (so em modo automatico), igual a _dns_view.
				ok, out = su.run(["ipconfig", "/all"])
				if ok:
					dns_atual = net.parse_ipcfg(out)["dns"]
			primario_atual = dns_atual[0] if dns_atual else None

			# A lista de candidatos agora e UNICA e gerenciavel pelo
			# usuario (ver _dns_manage) - na primeira vez que roda, ja vem
			# semeada com os provedores publicos conhecidos; dai em
			# diante e so o que o usuario definiu, sem nenhuma lista fixa
			# somada por baixo dos panos.
			candidatos = net.load_dns_list(self._dns_list_path())
			if not candidatos:
				wx.CallAfter(self._say, _(
					"Sua lista de servidores DNS está vazia. Adicione ao "
					"menos um em \"Gerenciar Servidores DNS\" antes de "
					"buscar o melhor."
				))
				return

			# extra_ip garante que o DNS ATUALMENTE em uso seja medido junto
			# com a lista, mesmo que ele nao esteja nela (ex.: o resolver
			# do proprio provedor de internet) - sem isso nao haveria como
			# comparar "seu DNS atual" com "o mais rapido encontrado" de
			# forma justa.
			resultados = net.find_best_dns(
				candidates=candidatos,
				extra_ip=primario_atual,
				timeout=config.conf["networkTools"]["dnsBestTimeout"],
				samples=config.conf["networkTools"]["dnsBestSamples"],
				finalists=config.conf["networkTools"]["dnsBestFinalists"])
			if not resultados:
				wx.CallAfter(self._say, _(
					"Nenhum dos servidores DNS testados respondeu. Verifique sua conexão com a internet."
				))
				return
			# O numero de candidatos testados de VERDADE (fase 1, rapida,
			# todos de uma vez) e maior que len(resultados) quando a busca
			# usa varias amostras por servidor (dnsBestSamples > 1) - nesse
			# caso "resultados" reflete so os FINALISTAS que passaram pra
			# fase 2 (teste profundo de estabilidade, ver find_best_dns em
			# netinfo.py, quantidade configuravel em dnsBestFinalists), nao
			# o total testado. Calcula aqui pra mostrar o numero certo na
			# mensagem, em vez de "len(resultados)" (finalistas) fazendo
			# parecer que so alguns poucos foram testados no total.
			total_testados = len(candidatos)
			if primario_atual and primario_atual not in candidatos:
				total_testados += 1
			wx.CallAfter(self._dns_best_result, resultados, primario_atual, total_testados)
		su.run_bg(worker)

	def _dns_best_result(self, resultados, primario_atual, total_testados):
		"""Roda na thread principal (via wx.CallAfter), depois que a busca
		em paralelo termina. resultados ja vem ordenado do mais rapido para
		o mais lento (net.find_best_dns) - mas so contem os FINALISTAS que
		passaram pra fase 2 (teste profundo com varias amostras), nao o
		total testado de verdade na fase 1; total_testados e esse numero
		real, calculado por quem chama, e e o que deve aparecer nas
		mensagens faladas para nao parecer que a busca testou menos
		servidores do que testou. Se o DNS atualmente em uso ja for o mais
		rapido encontrado, so informa isso - nao ha nada a trocar. Caso
		contrario, mostra um resumo com os melhores colocados e pergunta se
		o usuario quer trocar para o mais rapido (com o segundo colocado
		como secundario automatico, para nao perder a redundancia)."""
		melhor = resultados[0]
		if primario_atual and melhor["ip"] == primario_atual:
			if "jitter_ms" in melhor:
				self._say(_(
					"Seu DNS atual ({ip} - {provedor}) já é o mais rápido e "
					"estável entre os {n} servidores testados, com {ms} ms "
					"de latência e {j} ms de jitter. Nenhuma alteração é "
					"necessária."
				).format(
					ip=primario_atual, provedor=melhor["provider"] or primario_atual,
					n=total_testados, ms=melhor["latency_ms"], j=melhor["jitter_ms"],
				))
			else:
				self._say(_(
					"Seu DNS atual ({ip} - {provedor}) já é o mais rápido entre "
					"os {n} servidores testados, com {ms} ms de latência. "
					"Nenhuma alteração é necessária."
				).format(
					ip=primario_atual,
					provedor=melhor["provider"] or primario_atual,
					n=total_testados,
					ms=melhor["latency_ms"],
				))
			return

		linhas = []
		for i, r in enumerate(resultados[:10], start=1):
			# translators: marca o item da lista que corresponde ao DNS que o usuario ja esta usando agora
			marca = _(" (em uso agora)") if r["ip"] == primario_atual else ""
			# jitter_ms so vem preenchido quando a busca fez varias
			# consultas por servidor (dnsBestSamples > 1 nas
			# Configuracoes) - com uma consulta so nao ha jitter/perda
			# pra calcular, entao a linha fica so com a latencia, como
			# sempre foi.
			if "jitter_ms" in r:
				extra = _(", jitter {j} ms, perda {p}%").format(j=r["jitter_ms"], p=r["loss_pct"])
			else:
				extra = ""
			linhas.append("{n}. {ip} - {provedor} - {ms} ms{extra}{marca}".format(
				n=i, ip=r["ip"], provedor=r["provider"] or _("não identificado"),
				ms=r["latency_ms"], extra=extra, marca=marca,
			))
		latencia_atual = next((r["latency_ms"] for r in resultados if r["ip"] == primario_atual), None)
		if primario_atual and latencia_atual is not None:
			atual_txt = _("Seu DNS atual é {ip} ({ms} ms).").format(ip=primario_atual, ms=latencia_atual)
		elif primario_atual:
			atual_txt = _("Seu DNS atual ({ip}) não respondeu dentro do tempo limite.").format(ip=primario_atual)
		else:
			atual_txt = _("Não foi possível determinar seu DNS atual.")
		segundo = resultados[1] if len(resultados) > 1 else None
		pergunta = _(
			"Deseja definir {ip_melhor} ({provedor}) como seu novo servidor "
			"DNS primário{sec_txt}?"
		).format(
			ip_melhor=melhor["ip"],
			provedor=melhor["provider"] or melhor["ip"],
			sec_txt=_(" (e {ip} como secundário)").format(ip=segundo["ip"]) if segundo else "",
		)
		gui.mainFrame.prePopup()
		with dlg.DnsBestDialog(gui.mainFrame, _("Melhor DNS Encontrado"), linhas, atual_txt, pergunta) as d:
			ret = d.ShowModal()
		gui.mainFrame.postPopup()
		if ret != wx.ID_YES:
			self._back()
			return
		if not su.is_admin():
			self._no_admin()
			return
		iface = self._resolve_iface() or net.active_iface()
		if not iface:
			ui.message(_("Interface não detectada."))
			self._back()
			return
		secundario = segundo["ip"] if segundo else None
		ui.message(_("Aplicando DNS, aguarde."))
		def worker():
			rc, out, rc_sec, out_sec = net.apply_dns(iface, melhor["ip"], secundario)
			if rc == 0:
				linhas2 = [
					(_("Interface"),    iface),
					(_("DNS primário"), "{ip} — {ms} ms".format(ip=melhor["ip"], ms=melhor["latency_ms"])),
				]
				if secundario:
					linhas2.append((_("DNS secundário"), secundario))
					if rc_sec != 0:
						linhas2.append((_("Aviso"), _("Não foi possível configurar o DNS secundário: {detail}").format(detail=(out_sec or "").strip()[:150])))
				linhas2.append((_("Status"), _("✔ Aplicado com sucesso")))
				wx.CallAfter(self._show, _("Melhor DNS Aplicado"), su.fmt(*linhas2))
			else:
				wx.CallAfter(self._say, _(
					"Erro ao aplicar a configuração: {detail}"
				).format(detail=(out or "").strip()[:150]))
		su.run_bg(worker)

	def _dns_apply(self):
		if not su.is_admin():
			self._no_admin()
			return
		iface = self._resolve_iface() or net.active_iface()
		if not iface:
			ui.message(_("Interface não detectada."))
			self._back()
			return
		gui.mainFrame.prePopup()
		with dlg.CustomDNSDialog(gui.mainFrame, _("Aplicar DNS Personalizado")) as d:
			ret = d.ShowModal()
			primario, secundario = d.primario, d.secundario
		gui.mainFrame.postPopup()
		if ret != wx.ID_OK:
			self._back()
			return
		if not primario:
			ui.message(_("Informe o DNS primário."))
			self._back()
			return
		for label, val in ((_("DNS primário"), primario), (_("DNS secundário"), secundario)):
			if not val:
				continue
			try:
				ipaddress.ip_address(val)
			except ValueError:
				ui.message(_("IP inválido em {campo}: {valor}").format(campo=label, valor=val))
				self._back()
				return

		# translators: mensagem de progresso do teste previo (sem alterar o sistema) antes de aplicar um DNS personalizado
		ui.message(_("Testando o servidor DNS {ip}, aguarde.").format(ip=primario))
		def worker():
			# Consulta DNS crua enviada diretamente ao IP digitado, sem
			# tocar em nenhuma configuracao do sistema - se o roteador ou
			# o provedor de internet estiver bloqueando a porta 53, isto
			# falha (devolve None) sem nunca ter mudado nada na maquina.
			latencia = net.measure_dns_latency(primario)
			if latencia is not None:
				# O secundario e testado so de forma informativa - o
				# resultado dele NAO impede a aplicacao (o Windows aceita
				# um secundario mesmo que ele nao responda agora; pode vir
				# a responder depois, ou so ser usado como reserva).
				latencia_sec = net.measure_dns_latency(secundario) if secundario else None
				rc, out, rc_sec, out_sec = net.apply_dns(iface, primario, secundario or None)
				if rc == 0:
					linhas = [
						(_("Interface"),         iface),
						(_("DNS primário"),      primario),
						(_("Latência do teste"), _("{ms} ms").format(ms=latencia)),
					]
					if secundario:
						sec_txt = _("{ms} ms").format(ms=latencia_sec) if latencia_sec is not None else _("sem resposta ao teste (configurado mesmo assim)")
						linhas.append((_("DNS secundário"), f"{secundario} — {sec_txt}"))
						if rc_sec != 0:
							linhas.append((_("Aviso"), _("Não foi possível configurar o DNS secundário: {detail}").format(detail=(out_sec or "").strip()[:150])))
					# translators: confirmacao textual de sucesso (equivalente ao indicador visual verde, mas legivel por leitor de tela)
					linhas.append((_("Status"), _("✔ Aplicado com sucesso (porta 53 disponível)")))
					wx.CallAfter(self._show, _("DNS Personalizado Aplicado"), su.fmt(*linhas))
				else:
					wx.CallAfter(self._say, _(
						"O teste funcionou, mas houve erro ao aplicar a configuração: {detail}"
					).format(detail=(out or "").strip()[:150]))
				return
			# Teste direto falhou - normalmente indica que o roteador ou o
			# provedor de internet esta bloqueando a porta 53.
			wx.CallAfter(self._dns_blocked, iface, primario, secundario)
		su.run_bg(worker)

	def _dns_manage(self):
		"""Abre uma caixa de texto multi-linha (um IP por linha) com TODOS
		os servidores DNS que a Busca de Melhor DNS testa - os que vieram
		por padrao (provedores publicos conhecidos) E os que o usuario ja
		tiver adicionado antes, todos juntos na mesma lista. Editar,
		adicionar ou remover QUALQUER linha livremente, inclusive as que
		vieram por padrao - nao existe mais distincao entre "lista fixa
		do addon" e "lista personalizada": a partir da primeira vez que
		esta tela e usada, o arquivo E a lista completa. Mostrar os
		padroes aqui tambem evita que o usuario adicione, sem querer, um
		servidor que o addon ja testa (nao ha como saber isso de cabeca
		sem ver a lista completa).

		So aceita IPv4 (mesma limitacao de find_best_dns, que so testa
		IPv4) e nao aceita duplicata - uma linha invalida ou repetida e
		recusada com aviso claro de qual linha foi, em vez de salvar uma
		lista parcialmente correta.

		Ao terminar (salvo com sucesso, erro de validacao, ou
		cancelado), volta direto para o submenu de DNS - excecao
		deliberada ao padrao geral de _say() (que normalmente NAO reabre
		menu nenhum, pra nao cortar a fala em cima da troca de foco) -
		aqui o retorno automatico foi pedido explicitamente, entao a
		fala roda primeiro e so depois o menu reabre."""
		caminho = self._dns_list_path()
		atuais = net.load_dns_list(caminho)
		gui.mainFrame.prePopup()
		with dlg.EditableListDialog(
			gui.mainFrame,
			_("Gerenciar Servidores DNS"),
			_(
				"Um endereço IPv4 por linha - inclui os servidores padrão e "
				"os que você já adicionou. Edite, adicione ou remova "
				"livremente (inclusive os padrão). Esses são os servidores "
				"testados na próxima Busca de Melhor DNS. Deixe em branco "
				"para não ter nenhum."
			),
			"\n".join(atuais),
		) as d:
			ret = d.ShowModal()
			texto = d.value
		gui.mainFrame.postPopup()
		if ret != wx.ID_OK:
			self._back()
			return
		ok, motivo = net.save_dns_list(caminho, texto)
		if ok:
			n = len(net.load_dns_list(caminho))
			if n == 0:
				ui.message(_(
					"Lista salva vazia - a Busca de Melhor DNS não vai ter "
					"nenhum servidor para testar até que você adicione algum aqui."
				))
			else:
				ui.message(_(
					"Lista salva - {n} servidor(es) DNS."
				).format(n=n))
		else:
			ui.message(motivo or _("Não foi possível salvar a lista."))
		self._back()

	def _dns_test_one(self):
		"""Testa UM UNICO servidor DNS avulso, digitado na hora - nao
		afeta a lista gerenciada (ver _dns_manage) nem a configuracao de
		DNS do sistema, e um diagnostico isolado. O teste envia uma
		consulta DNS de verdade via UDP na porta 53 direto pro servidor
		informado (net.measure_dns_latency_multi - mesmo mecanismo usado
		pela Busca de Melhor DNS, NAO e ping/ICMP), mostrando media,
		minima, maxima, jitter e perda.

		Quantidade de consultas (dnsTestOneSamples, padrao 10 - mais
		minucioso que o padrao da Busca de Melhor DNS, ja que aqui e so
		UM servidor, nao ha custo de multiplicar por varios finalistas)
		e tempo limite (dnsTestOneTimeout) tem CONFIGURACOES PROPRIAS,
		separadas de dnsBestSamples/dnsBestTimeout - assim testar um
		servidor especifico com mais rigor nao deixa a Busca de Melhor
		DNS mais lenta (que multiplicaria esse custo por varios
		finalistas de uma vez)."""
		ip = self._ask(_("Testar um Servidor DNS"), _("Endereço IPv4 do servidor DNS:"))
		if not ip:
			self._back()
			return
		try:
			ipaddress.IPv4Address(ip)
		except ValueError:
			ui.message(_("Endereço IPv4 inválido: {ip}").format(ip=ip))
			self._back()
			return
		amostras = config.conf["networkTools"]["dnsTestOneSamples"]
		tempo_limite = config.conf["networkTools"]["dnsTestOneTimeout"]
		ui.message(_("Testando {ip}, aguarde.").format(ip=ip))
		def worker():
			stats = net.measure_dns_latency_multi(ip, samples=amostras, timeout=tempo_limite)
			provedor = net.identify_dns_provider(ip)
			if stats["avg"] is None:
				wx.CallAfter(self._say, _(
					"{ip} não respondeu a nenhuma das {n} consultas."
				).format(ip=ip, n=amostras))
				return
			wx.CallAfter(self._show, _("Teste de Servidor DNS"), "\n".join([
				_("Servidor: {ip}{provedor}").format(
					ip=ip, provedor=f" - {provedor}" if provedor else ""),
				_("Latência média: {ms} ms").format(ms=stats["avg"]),
				_("Mínima: {ms} ms").format(ms=stats["min"]),
				_("Máxima: {ms} ms").format(ms=stats["max"]),
				_("Jitter: {j} ms").format(j=stats["jitter"]),
				_("Perda: {p}% ({recv} de {sent} consultas responderam)").format(
					p=stats["loss"], recv=stats["recv"], sent=stats["sent"]),
			]))
		su.run_bg(worker)

	def _dns_blocked(self, iface, ip, secundario=None):
		template = net.doh_template_for(ip)
		if not template:
			self._say(_(
				"Não foi possível confirmar o DNS {ip} pela porta 53 (isso "
				"costuma indicar bloqueio pelo roteador ou pelo provedor de "
				"internet). O Modo Seguro (DNS via HTTPS) não está disponível "
				"para este servidor, porque ele não é um provedor público com "
				"suporte documentado a DNS criptografado. Tente novamente com "
				"um provedor como Google (8.8.8.8), Cloudflare (1.1.1.1) ou "
				"Quad9 (9.9.9.9)."
			).format(ip=ip))
			return
		if not self._confirm(
			_("Porta 53 Bloqueada"),
			_(
				"DNS {ip} não respondeu pela porta 53 (provável bloqueio "
				"do roteador ou provedor). Ativar Modo Seguro (DNS via "
				"HTTPS, porta 443)?"
			).format(ip=ip)
		):
			self._back()
			return
		ui.message(_("Testando DNS via HTTPS (Modo Seguro), aguarde."))
		def worker():
			ok = net.test_doh(ip)
			if not ok:
				wx.CallAfter(self._say, _(
					"O Modo Seguro também não funcionou: o servidor {ip} não "
					"respondeu pela porta 443 (HTTPS). Isso pode indicar um "
					"bloqueio mais amplo da rede, ou que o serviço esteja "
					"temporariamente indisponível."
				).format(ip=ip))
				return
			rc, out = net.enable_doh(ip, template)
			if rc != 0:
				wx.CallAfter(self._say, _(
					"O teste via HTTPS funcionou, mas este Windows não aceitou "
					"o registro de DNS criptografado: {detail} Esse recurso "
					"requer uma versão mais recente do Windows 10 ou 11."
				).format(detail=(out or "").strip()[:150]))
				return
			rc2, out2, rc_sec, out_sec = net.apply_dns(iface, ip, secundario)
			if rc2 == 0:
				linhas = [
					(_("Interface"),    iface),
					(_("Servidor DNS"), ip),
					(_("Modo"),         _("DNS via HTTPS (DoH)")),
				]
				if secundario:
					linhas.append((_("DNS secundário"), secundario))
					if rc_sec != 0:
						linhas.append((_("Aviso"), _("Não foi possível configurar o DNS secundário: {detail}").format(detail=(out_sec or "").strip()[:150])))
					else:
						# translators: aviso de que o DNS secundario continua usando porta 53 tradicional, mesmo com o Modo Seguro ativo no primario
						linhas.append((_("Aviso"), _(
							"O DNS secundário usa a porta 53 tradicional, não o Modo "
							"Seguro - se o mesmo bloqueio afetar esse servidor, o "
							"Windows deve usar o primário normalmente."
						)))
				# translators: confirmacao textual de sucesso do Modo Seguro (equivalente ao indicador visual verde, mas legivel por leitor de tela)
				linhas.append((_("Status"), _("✔ Proteção ativa — bloqueio de porta 53 contornado")))
				wx.CallAfter(self._show, _("Modo Seguro Ativo"), su.fmt(*linhas))
			else:
				wx.CallAfter(self._say, _("Erro ao aplicar o DNS: {detail}").format(detail=(out2 or "").strip()[:150]))
		su.run_bg(worker)

	def _wifi(self):
		ui.message(_("Consultando Wi-Fi, aguarde."))
		def cb_iface(ok, out):
			if not ok or not out.strip():
				wx.CallAfter(self._say, _("Nenhuma rede Wi-Fi."))
				return
			# O Windows recusa dados de WLAN via WlanQueryInterface quando o
			# servico de Localizacao do sistema esta desativado nas
			# configuracoes de privacidade - o netsh roda normalmente, mas
			# devolve um aviso em vez do bloco de interface. "WlanQueryInterface"
			# e o URI "privacy-location" sao identificadores tecnicos que o
			# Windows nao traduz em nenhum idioma, entao servem de marcador
			# confiavel independente de locale (mesmo principio das outras
			# deteccoes estruturais do projeto). Sem este checkpoint, o texto
			# de erro cai direto no parser de wifi_interfaces(), que nao acha
			# nenhum bloco "Nome:" valido e reporta erroneamente "Nenhuma rede
			# Wi-Fi.", mascarando a causa real (permissao do Windows).
			if "WlanQueryInterface" in out or "privacy-location" in out:
				wx.CallAfter(self._say, _(
					"O Windows está bloqueando o acesso às informações de "
					"Wi-Fi porque o serviço de Localização do sistema está "
					"desativado. Abra as Configurações, vá em Privacidade e "
					"segurança, Localização, e ative o serviço de "
					"Localização. Depois tente novamente."
				))
				return
			adapters = net.wifi_interfaces(out)
			if not adapters:
				wx.CallAfter(self._say, _("Nenhuma rede Wi-Fi."))
				return
			resolved = self._resolve_iface()
			if resolved:
				# Interface escolhida manualmente: so mostra dados se ela
				# for de fato um dos radios Wi-Fi listados aqui. Antes,
				# escolher uma interface nao-Wi-Fi (Ethernet, vEthernet
				# etc.) fazia esta tela cair silenciosamente no Wi-Fi
				# conectado mais proximo, misturando dados de adaptadores
				# diferentes - cada adaptador tem que ser independente.
				chosen = next((a for a in adapters if a["name"] == resolved), None)
				if chosen is None:
					wx.CallAfter(self._say, _(
						"A interface selecionada ({iface}) não é um adaptador Wi-Fi."
					).format(iface=resolved))
					return
			else:
				# Modo automatico: sem uma escolha explicita, prefere o
				# primeiro radio Wi-Fi realmente conectado a uma rede;
				# sem nenhum conectado, cai no primeiro da lista (preserva
				# o diagnostico de "sem Wi-Fi" de sempre).
				chosen = next((a for a in adapters if a["connected"] and a["ssid"]), None)
				if chosen is None:
					chosen = adapters[0]
			block = chosen["block"]
			ssid = chosen["ssid"] or "?"
			# Sem SSID: nao ha rede Wi-Fi ativa no momento. Antes de mostrar
			# uma tela cheia de "?"/"nao detectado", verifica se a conexao
			# em uso agora e por cabo Ethernet (ou outro adaptador nao-Wi-Fi)
			# para dar uma mensagem clara em vez de campos vazios.
			if ssid == "?":
				active_iface = net.active_iface()
				if active_iface and not rx.RX_WIFI_IFACE_NAME.search(active_iface):
					wx.CallAfter(self._say, _(
						"Conectado via cabo Ethernet (adaptador: {iface}). "
						"Nenhuma rede Wi-Fi ativa no momento."
					).format(iface=active_iface))
				else:
					wx.CallAfter(self._say, _(
						"Nenhuma rede Wi-Fi conectada no momento."
					))
				return
			sig  = (m := rx.RX_SIGNAL.search(block)) and m.group(1) + "%" or "?"
			auth = (m := rx.RX_AUTH.search(block)) and m.group(1).strip() or "?"
			bssid   = (m := rx.RX_WLAN_BSSID.search(block)) and m.group(1)
			channel = (m := rx.RX_WLAN_CHANNEL.search(block)) and m.group(1)
			radio   = (m := rx.RX_WLAN_RADIO.search(block)) and m.group(1).strip()
			rate    = (m := rx.RX_WLAN_RATE.search(block)) and m.group(1).strip()
			def cb_prof(ok2, out2):
				pwd = (m := rx.RX_KEY.search(out2)) and m.group(1).strip() if ok2 else None
				wx.CallAfter(self._show, _("Wi-Fi"), su.fmt(
					(_("Adaptador"),     chosen["name"]),
					(_("Rede"),          ssid),
					(_("Sinal"),         sig),
					(_("Autenticação"),  auth),
					(_("Canal"),         channel or _("não detectado")),
					(_("Tipo de rádio"), radio or _("não detectado")),
					(_("BSSID (roteador)"), bssid or _("não detectado")),
					(_("Velocidade do link Wi-Fi"), _("{v} Mbps").format(v=rate) if rate else _("não detectada")),
					(_("Senha"),         pwd or _("não disponível (requer Admin)")),
				))
			su.run_async(["netsh","wlan","show","profile",f"name={ssid}","key=clear"], cb_prof)
		su.run_async(["netsh","wlan","show","interfaces"], cb_iface)

	def _pub_ip(self):
		ui.message(_("Buscando IP público, aguarde."))
		def worker():
			ip = net.public_ip_nslookup()
			if ip:
				# translators: {ip} e substituido pelo endereco IP encontrado
				wx.CallAfter(self._show, _("IP Público"), _("IP Público: {ip}").format(ip=ip))
				return
			for url in ["https://api.ipify.org?format=json","https://checkip.amazonaws.com","https://icanhazip.com"]:
				ok, body = su.http(url, 8)
				if not ok or not body.strip():
					continue
				c = body.strip()
				try:
					c = json.loads(body).get("ip", c)
				except Exception:
					pass
				if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", c):
					wx.CallAfter(self._show, _("IP Público"), _("IP Público: {ip}").format(ip=c))
					return
			wx.CallAfter(self._say, _("Não foi possível obter o IP público."))
		su.run_bg(worker)

	# --- Modulo B ---

	def _ping(self):
		padrao_count = config.conf["networkTools"]["pingDefaultCount"]
		host, count_txt, porta_txt = self._ask_target_param(
			_("Ping"),
			# translators: rotulo do campo de destino do ping
			_("Endereço ou IP para pingar:"), "8.8.8.8",
			# translators: rotulo do campo opcional de quantidade de pacotes do ping (o {default} mostra o padrao configurado em Preferencias > Configuracoes, usado se ficar em branco)
			_("Número de pacotes (deixe em branco para usar o padrão: {default}):").format(default=padrao_count),
			# translators: rotulo do campo opcional de porta TCP - em branco usa ping ICMP normal; preenchido, testa alcance de uma porta especifica em vez de so o host
			_("Porta TCP (opcional - deixe em branco para ping ICMP normal):"),
		)
		if host is None:
			self._back()
			return
		t = host or "8.8.8.8"
		if not self._host_seguro(t):
			ui.message(_("Endereço ou host inválido: {host}").format(host=t))
			self._back()
			return
		# Teto alto o suficiente para nao atrapalhar pedidos legitimos
		# (30, 64, 100...) - o ping.exe em si nao tem um limite baixo de
		# verdade, o unico limite pratico e o tempo que voce quer esperar.
		count = self._parse_int_or_default(count_txt, default=padrao_count, min_v=1, max_v=1000)

		porta_txt = (porta_txt or "").strip()
		porta = None
		if porta_txt:
			porta = self._parse_int_or_default(porta_txt, default=None, min_v=1, max_v=65535)
			if porta is None:
				ui.message(_(
					"Porta inválida - use um número entre 1 e 65535, ou "
					"deixe o campo em branco para ping ICMP normal."
				))
				self._back()
				return

		if porta:
			# Ping "TCP" - mesma apresentacao de resultado do ICMP abaixo
			# (net.tcp_ping devolve o mesmo formato de net.ping_parse), so
			# que testando uma PORTA especifica via socket puro, sem
			# depender de ping.exe nem de nenhum processo externo.
			ui.message(_("Testando porta TCP {porta} de {host}, aguarde.").format(porta=porta, host=t))
			def worker_tcp():
				d = net.tcp_ping(t, porta, count=count)
				if not d.get("recv"):
					wx.CallAfter(self._say, _("Sem resposta de {host} na porta {porta}.").format(host=t, porta=porta))
					return
				status_label = {
					"excellent": _("Excelente"),
					"stable":    _("Estável"),
					"unstable":  _("Instável"),
				}.get(d.get("status"), _("não determinado"))
				dest_ip = d.get("dest_ip")
				mesmo_ip = dest_ip == t
				wx.CallAfter(self._show, _("Ping TCP - {host}:{porta}").format(host=t, porta=porta), su.fmt(
					(_("Destino") if not mesmo_ip else None, t if not mesmo_ip else None),
					(_("IP de destino"),      dest_ip),
					(_("Pacotes enviados"),   d.get("sent")),
					(_("Pacotes recebidos"),  d.get("recv")),
					(_("Perda de pacotes"),   _("{loss}%").format(loss=d.get("loss"))),
					(_("Latência mínima"),    _("{v} ms").format(v=d.get("min")) if d.get("min") is not None else None),
					(_("Latência média"),     _("{avg} ms").format(avg=d.get("avg"))),
					(_("Latência máxima"),    _("{v} ms").format(v=d.get("max")) if d.get("max") is not None else None),
					(_("Desvio padrão"),      _("{v} ms").format(v=d.get("std")) if d.get("std") is not None else None),
					(_("Jitter"),             _("{v} ms").format(v=d.get("jitter")) if d.get("jitter") is not None else None),
					(_("TTL"),                d.get("ttl")),
					(_("Status"),             status_label),
				))
			su.run_bg(worker_tcp)
			return

		# O timeout do comando precisa crescer com a quantidade de
		# pacotes, senao pedir mais pacotes do que o padrao corta o ping
		# no meio antes de terminar.
		timeout = max(15, count * 2)
		ui.message(_("Ping para {host}, aguarde.").format(host=t))
		def worker():
			d = net.ping_parse(t, count=count, timeout=timeout)
			if d is not None:
				if not d.get("recv"):
					wx.CallAfter(self._say, _("Sem resposta de {host}.").format(host=t))
					return
				status_label = {
					"excellent": _("Excelente"),
					"stable":    _("Estável"),
					"unstable":  _("Instável"),
				}.get(d.get("status"), _("não determinado"))
				dest_ip = d.get("dest_ip")
				# Quando o destino digitado ja e um IP (nao um nome), o
				# ping nao "resolve" nada de fato - "Destino" e "IP de
				# destino" ficam identicos. Mostrar os dois nesse caso e
				# so redundancia; colapsa numa linha so.
				mesmo_ip = dest_ip == t
				wx.CallAfter(self._show, _("Ping - {host}").format(host=t), su.fmt(
					(_("Destino") if not mesmo_ip else None, t if not mesmo_ip else None),
					(_("IP de destino"),      dest_ip),
					(_("Pacotes enviados"),   d.get("sent")),
					(_("Pacotes recebidos"),  d.get("recv")),
					(_("Perda de pacotes"),   _("{loss}%").format(loss=d.get("loss"))),
					(_("Latência mínima"),    _("{v} ms").format(v=d.get("min")) if d.get("min") is not None else None),
					(_("Latência média"),     _("{avg} ms").format(avg=d.get("avg"))),
					(_("Latência máxima"),    _("{v} ms").format(v=d.get("max")) if d.get("max") is not None else None),
					(_("Desvio padrão"),      _("{v} ms").format(v=d.get("std")) if d.get("std") is not None else None),
					(_("Jitter"),             _("{v} ms").format(v=d.get("jitter")) if d.get("jitter") is not None else None),
					(_("TTL"),                d.get("ttl")),
					(_("Status"),             status_label),
				))
				return
			# Reserva: ping.exe por texto (so reconhece ES/EN/PT)
			ok, out = su.run(["ping", "-n", str(count), t], timeout + 15)
			if not ok:
				wx.CallAfter(self._say, _("Erro ao pingar {host}.").format(host=t))
				return
			avg  = (m := rx.RX_PING_AVG.search(out)) and m.group(1)
			loss = (m := rx.RX_PING_LOSS.search(out)) and str(int(m.group(1))*25) or "0"
			ttls = [int(x) for x in rx.RX_PING_TTL.findall(out)]
			ttl = ttls[0] if ttls else None
			dest_m = rx.RX_PING_DEST_IP.search(out)
			dest_ip = dest_m.group(1) if dest_m else t
			if not avg:
				wx.CallAfter(self._say, _("Sem resposta de {host}.").format(host=t))
				return
			wx.CallAfter(self._show, _("Ping - {host}").format(host=t), su.fmt(
				(_("Destino"),          t),
				(_("IP de destino"),    dest_ip),
				(_("Latência média"),   _("{avg} ms").format(avg=avg)),
				(_("TTL"),              ttl),
				(_("Perda de pacotes"), _("{loss}%").format(loss=loss)),
			))
		su.run_bg(worker)

	# --- Modulo IPv6 ---
	# O Windows mostra o endereco IPv6 configurado na interface, mas nunca
	# diz se ele realmente funciona. Um adaptador pode ter um endereco
	# IPv6 global perfeitamente valido e mesmo assim nao conseguir sair
	# para a internet (roteador que nao repassa, provedor que bloqueia,
	# ou so o link-local de sempre). Estes quatro testes existem para
	# responder "funciona de verdade?" em vez de so "existe um endereco?".

	def _ipv6_conn(self):
		ui.message(_("Testando conectividade IPv6, aguarde."))
		def worker():
			iface = self._resolve_iface() or net.active_iface()
			addrs = net.ipv6_addresses(iface) if iface else {"global": None, "link_local": None}
			if not addrs["global"] and not addrs["link_local"]:
				wx.CallAfter(self._say, _("Nenhum endereço IPv6 encontrado nesta interface."))
				return
			ok, provedor = net.ipv6_connectivity_test()
			if ok:
				resultado = _("IPv6 funcionando: conexão de saída para a internet confirmada.")
			else:
				resultado = _("IPv6 presente, mas sem conexão.")
			wx.CallAfter(self._show, _("Teste de Conectividade IPv6"), su.fmt(
				(_("Endereço IPv6 global"), addrs["global"] or _("nenhum")),
				(_("Endereço IPv6 local (link-local)"), addrs["link_local"] or _("nenhum")),
				(_("Testado contra"), provedor or _("nenhum servidor respondeu")),
				(_("Resultado"), resultado),
			))
		su.run_bg(worker)

	def _ipv6_dns(self):
		# translators: titulo do dialogo que pede o dominio para testar a resolucao IPv6
		host = self._ask(_("Teste de DNS IPv6"), _("Domínio para testar:"), "google.com")
		if host is None:
			self._back()
			return
		ui.message(_("Testando DNS IPv6 para {host}, aguarde.").format(host=host))
		def worker():
			r = net.ipv6_dns_test(host)
			if not r["resolved"]:
				wx.CallAfter(self._show, _("Teste de DNS IPv6"), su.fmt(
					(_("Domínio"), host),
					(_("Resultado"), _("O DNS não retornou nenhum endereço IPv6 (AAAA) para este domínio.")),
				))
				return
			if r["connected"]:
				resultado = _("DNS IPv6 ok, conexão IPv6 funcionando.")
			else:
				resultado = _("DNS IPv6 ok, conexão IPv6 quebrada.")
			wx.CallAfter(self._show, _("Teste de DNS IPv6"), su.fmt(
				(_("Domínio"), host),
				(_("Endereço IPv6 resolvido"), r["address"]),
				(_("Resultado"), resultado),
			))
		su.run_bg(worker)

	def _ipv6_diag(self):
		ui.message(_("Executando diagnóstico completo de IPv6, aguarde."))
		def worker():
			iface = self._resolve_iface() or net.active_iface()
			addrs = net.ipv6_addresses(iface) if iface else {"global": None, "link_local": None}
			has_gw, gw_addr = net.ipv6_default_route()
			ok, provedor = net.ipv6_connectivity_test()
			if ok:
				conclusao = _("IPv6 funcionando.")
			elif addrs["global"]:
				# Tem endereco global (ou seja, recebeu prefixo do roteador),
				# mas mesmo assim nao chega na internet.
				conclusao = _("IPv6 presente, mas sem internet.")
			elif has_gw:
				# Existe uma rota padrao IPv6 anunciada na rede (o roteador
				# sabe encaminhar para fora), mas este dispositivo nao
				# recebeu um endereco global proprio.
				conclusao = _("Roteador não entrega IPv6.")
			else:
				# Nenhuma rota, nenhum endereco global: nada na rede local
				# esta anunciando IPv6 utilizavel.
				conclusao = _("Provedor não oferece IPv6.")
			wx.CallAfter(self._show, _("Diagnóstico IPv6 Completo"), su.fmt(
				(_("Endereço IPv6 global"), addrs["global"] or _("nenhum")),
				(_("Endereço IPv6 local (link-local)"), addrs["link_local"] or _("nenhum")),
				(_("Rota padrão IPv6 na rede"), _("sim") if has_gw else _("não")),
				(_("Conectividade de saída"), _("confirmada") if ok else _("falhou")),
				(_("Conclusão"), conclusao),
			))
		su.run_bg(worker)

	def _tracert(self):
		padrao_hops = config.conf["networkTools"]["tracertDefaultHops"]
		host, hops_txt, proto_txt = self._ask_target_param(
			_("Traceroute"),
			_("Endereço de destino:"), "google.com",
			_("Limite de saltos (deixe em branco para usar o padrão: {default}):").format(default=padrao_hops),
			_("Protocolo - digite 4 para IPv4, 6 para IPv6, ou deixe em branco para automático:"),
		)
		if host is None:
			self._back()
			return
		if not self._host_seguro(host):
			ui.message(_("Endereço ou host inválido: {host}").format(host=host))
			self._back()
			return
		MAX_HOPS = self._parse_int_or_default(hops_txt, default=padrao_hops, min_v=1, max_v=64)
		# Sem forcar -4/-6 (protocolo em branco = "automatico"), o Windows
		# decide sozinho qual protocolo usar, baseado em qual registro o
		# DNS devolver primeiro - o mesmo destino pode sair como IPv4 ou
		# IPv6 dependendo da rede do usuario, o que pode confundir mais do
		# que ajudar (confirmado ao vivo: o usuario esperava ver um
		# endereco e o Windows tracejou por IPv6 sem avisar). Deixar
		# escolher explicitamente da previsibilidade a quem quiser - "4"
		# forca -4 (so IPv4), "6" forca -6 (so IPv6), qualquer outra coisa
		# (inclusive em branco) mantem o automatico de sempre.
		proto_flag = None
		proto_txt_limpo = (proto_txt or "").strip()
		if proto_txt_limpo == "4":
			proto_flag = "-4"
		elif proto_txt_limpo == "6":
			proto_flag = "-6"
		comando = ["tracert", "-h", str(MAX_HOPS)]
		if proto_flag:
			comando.append(proto_flag)
		comando += ["-d", host]
		ui.message(_("Traceroute para {host}. Bipes a cada salto.").format(host=host))
		def worker():
			# IMPORTANTE: usamos Popen + leitura linha a linha em vez de
			# su.run()/subprocess.run(). O subprocess.run so devolve o texto
			# depois que o tracert termina por completo, entao os bipes
			# antigos disparavam todos de uma vez, em rajada, junto com a
			# abertura do dialogo de resultado — e por isso pareciam nao
			# soar. Lendo linha a linha, cada bipe soa no momento em que
			# aquele salto realmente responde, com o mesmo espacamento
			# real da rede.
			hops = []  # cada item: {"n", "ip" (ou None se sem resposta), "ms" (ou None)}
			try:
				proc = subprocess.Popen(
					comando,
					stdout=subprocess.PIPE,
					stderr=subprocess.STDOUT,
					creationflags=subprocess.CREATE_NO_WINDOW,
				)
			except Exception:
				wx.CallAfter(self._say, _("Erro no traceroute."))
				return
			try:
				for raw_line in iter(proc.stdout.readline, b""):
					line = su.decode_console_bytes(raw_line)
					if line is None:
						continue
					m = rx.RX_TRACERT.match(line)
					if m:
						n, times_str, ip = m.group(1), m.group(2), m.group(3)
						ms_list = [int(x) for x in rx.RX_TRACERT_MS.findall(times_str)]
						if ms_list:
							# Salto respondeu: guarda o IP real e a media.
							avg_ms = round(sum(ms_list) / len(ms_list))
							hops.append({"n": n, "ip": ip, "ms": avg_ms})
						else:
							# Timeout total (3 asteriscos): o "ip" capturado
							# pela regex aqui NAO e um endereco de verdade -
							# e so a primeira palavra da mensagem localizada
							# de timeout do Windows (ex.: "Tiempo de espera
							# agotado...", "Request timed out."). Um roteador
							# que nao responde a ICMP e normal e NAO e erro;
							# por isso registramos so como "sem resposta",
							# sem inventar um endereco.
							hops.append({"n": n, "ip": None, "ms": None})
						wx.CallAfter(tones.beep, 880, 60)
				# O tempo limite do processo precisa crescer com o limite de
				# saltos, senao pedir mais saltos do que o padrao corta o
				# traceroute no meio antes de terminar.
				proc.wait(timeout=max(120, MAX_HOPS * 4))
			except subprocess.TimeoutExpired:
				proc.kill()
			except Exception:
				pass
			finally:
				try:
					proc.stdout.close()
				except Exception:
					pass
			if not hops:
				wx.CallAfter(self._say, _("Nenhum salto encontrado."))
				return
			lines = []
			for h in hops:
				if h["ip"] is not None:
					lines.append(_("Salto {n}: {ip} - {ms} ms").format(n=h["n"], ip=h["ip"], ms=h["ms"]))
				else:
					# translators: salto do traceroute sem resposta (roteador que nao responde a ICMP, o que e normal)
					lines.append(_("Salto {n}: sem resposta (roteador não responde a ICMP)").format(n=h["n"]))
			# Verifica se o destino foi realmente alcancado. NAO comparamos
			# com um IP resolvido separadamente por nos (socket.gethostbyname):
			# dominios grandes (CDN/anycast, ex. google.com) podem devolver
			# um IP diferente a cada resolucao, entao essa comparacao falha
			# mesmo quando o tracert chegou no destino de verdade. O sinal
			# confiavel e outro: o tracert so encerra ANTES do limite de
			# saltos quando ele mesmo (com a sua propria resolucao) detecta
			# que chegou no destino, ou recebe um erro de rede inalcancavel.
			# Um timeout isolado no meio do caminho e normal (o salto
			# seguinte respondendo prova que o roteador anterior so nao
			# responde a ICMP, mas encaminha o trafego normalmente). So vale
			# destacar como possivel problema quando o destino NUNCA aparece
			# E os ultimos saltos, em sequencia, ficaram todos sem resposta.
			last_hop = hops[-1]
			reached_hop = last_hop["n"] if (len(hops) < MAX_HOPS and last_hop["ip"] is not None) else None
			trailing_timeouts = 0
			for h in reversed(hops):
				if h["ip"] is None:
					trailing_timeouts += 1
				else:
					break
			summary = _("Total: {n} saltos").format(n=len(hops))
			if reached_hop:
				summary += "\n" + _("Destino alcançado no salto {n}.").format(n=reached_hop)
			elif trailing_timeouts >= 3:
				summary += "\n" + _(
					"Destino não alcançado: os últimos {n} saltos não responderam."
				).format(n=trailing_timeouts)
			else:
				summary += "\n" + _("Destino não alcançado dentro do limite de saltos.")
			wx.CallAfter(self._show, _("Traceroute - {host}").format(host=host),
				summary + "\n\n" + "\n".join(lines))
		su.run_bg(worker)

	def _discover_devices(self):
		"""Descoberta de dispositivos na rede local (ping+ARP+portas, com
		verificacao cruzada contra a tabela ARP do sistema no final).

		Roda na thread de fundo de quem chamar (nao cria a propria) e
		devolve (found, arp): found e uma lista de IPs (str) ja ordenada;
		arp e o dict IP -> MAC lido no final. Em caso de erro (rede local
		nao detectada), ja avisa o usuario por conta propria e devolve
		(None, None) - quem chama so precisa checar "if found is None:
		return".

		Nao tenta resolver nome de aparelho (DNS reverso/NetBIOS) de
		proposito - na pratica, quase nunca resolve nada alem da propria
		maquina local (a maioria dos roteadores domesticos nao mantem
		registro de DNS reverso pros aparelhos da LAN, e NetBIOS so
		funciona pra Windows), entao o ganho real era pequeno pro custo
		de manter. O IP e o MAC (com fabricante, quando reconhecido) ja
		identificam o aparelho o suficiente pra fins de diagnostico de
		rede - MAC e o identificador realmente ESTAVEL de um aparelho,
		nome nao."""
		try:
			lip = net.local_ip()
			if not lip:
				raise OSError("sem IP local")
			p = lip.split(".")
			netw = ipaddress.IPv4Network(f"{p[0]}.{p[1]}.{p[2]}.0/24", False)
		except Exception:
			wx.CallAfter(self._say, _("Não foi possível detectar a rede local."))
			return None, None
		found = []
		# MACs capturados DIRETO da resposta do SendARP - ver o motivo
		# abaixo, em _one(). Guardado separado de "arp" (a tabela do
		# sistema) porque a fonte e diferente: isto e o que a PROPRIA
		# chamada devolveu, nao o que o Windows guardou depois.
		arp_extra = {}
		lock = threading.Lock()
		sem  = threading.Semaphore(50)
		def _portas_em_paralelo(ip, portas=(80, 443, 22, 445, 8080, 139, 5000), timeout=0.3):
			"""Testa varias portas TCP AO MESMO TEMPO (nao uma atras da
			outra) e devolve True assim que a primeira responder, ou
			False se nenhuma responder dentro do timeout. As 7 portas
			em sequencia custavam ate 7 x 0.3s = 2.1s por endereco SEM
			aparelho nenhum (o caso mais comum numa varredura de /24) -
			em paralelo, o pior caso cai pra so 0.3s, quase um setimo do
			tempo."""
			resultado = {"ok": False}
			def _uma(port):
				if resultado["ok"]:
					return
				try:
					# "with" fecha o socket explicitamente em qualquer
					# caso (sucesso, timeout ou recusa de conexao), em
					# vez de deixar para o coletor de lixo - importante
					# aqui porque a varredura abre muitos sockets em
					# sequencia rapida.
					with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
						s.settimeout(timeout)
						s.connect((ip, port))
					resultado["ok"] = True
				except OSError:
					pass
			ts_portas = [threading.Thread(target=_uma, args=(p,), daemon=True) for p in portas]
			for t in ts_portas: t.start()
			for t in ts_portas: t.join(timeout=timeout + 0.2)
			return resultado["ok"]
		def _one(ip_obj):
			with sem:
				ip = str(ip_obj)
				reachable = False
				# 1) Ping (ICMP) primeiro - timeout LIMITADO explicitamente
				# (400 ms via -w), o que importa muito numa varredura de
				# /24: a grande maioria dos 254 enderecos NAO tem
				# aparelho nenhum, entao o tempo total da varredura e
				# dominado pelo caso NEGATIVO (sem resposta), nao pelo
				# positivo.
				ok, out = su.run(["ping", "-n", "1", "-w", "400", ip], timeout=2)
				if ok and rx.RX_PING_TTL.search(out):
					reachable = True
				if not reachable:
					# 2) ARP ativo nativo (SendARP) - reserva pros que nao
					# responderam ping (aparelhos que bloqueiam ICMP mas
					# ainda assim estao conectados). timeout=1.0 (mais
					# generoso que o ping) porque alguns aparelhos - IoT
					# em modo economia de energia, por exemplo - demoram
					# mais pra "acordar" a placa de rede e responder; um
					# limite curto demais aqui cortava respostas
					# legitimas cedo demais (encontrado ao vivo no
					# hardware do usuario). su.send_arp ja tem o proprio
					# timeout embutido (a API do Windows nao oferece
					# essa opcao nativamente).
					#
					# IMPORTANTE: guarda o MAC que o PROPRIO SendARP
					# devolveu (arp_extra), em vez de confiar so na
					# releitura da tabela ARP do sistema no final - a
					# chamada ja devolve o MAC de brinde quando encontra
					# o aparelho, entao usar isso direto e estritamente
					# melhor que jogar fora e torcer pra ele reaparecer
					# numa releitura depois (custo zero: nao e uma
					# chamada extra, so aproveita o que ja veio).
					mac_arp = su.send_arp(ip, timeout=1.0)
					if mac_arp is not None:
						reachable = True
						with lock:
							arp_extra[ip] = mac_arp
				if not reachable:
					# 3) Ultima reserva: alguns aparelhos bloqueiam ICMP
					# mas tem servicos abertos - tenta portas comuns, TODAS
					# em paralelo (ver _portas_em_paralelo acima).
					if _portas_em_paralelo(ip):
						reachable = True
				if reachable:
					with lock:
						found.append(ip)
		ts = [threading.Thread(target=_one, args=(h,), daemon=True) for h in netw.hosts()]
		for t in ts: t.start()
		for t in ts: t.join()

		# Verificacao cruzada: le a tabela ARP do SISTEMA (nao a nossa,
		# a do Windows) depois que a varredura inteira termina. Ela
		# reflete qualquer troca de pacote que aconteceu com um
		# endereco local, independente de qual dos 3 metodos acima
		# pegou (ou nao pegou) aquele aparelho especifico - cobre o
		# caso em que um timeout individual (ping ou ARP) desistiu
		# cedo demais de um aparelho, mas a resolucao terminou em
		# segundo plano a tempo de aparecer aqui antes do fim da
		# varredura. Isto e o que responde "como saber se o resultado
		# esta certo": qualquer endereco da mesma sub-rede que aparece
		# na tabela ARP do sistema, mas que os 3 metodos individuais
		# não pegaram, e recuperado aqui em vez de ficar de fora.
		arp = net.arp_table()
		# Funde os MACs capturados direto do SendARP (arp_extra) - dado
		# que ja tinhamos na mao, sem custo de chamada nenhuma extra.
		# setdefault: se o mesmo IP tambem estiver na tabela do sistema,
		# mantem o valor de la (deveria ser o mesmo MAC de qualquer
		# forma).
		for ip_extra, mac_extra in arp_extra.items():
			arp.setdefault(ip_extra, mac_extra)
		found_set = set(found)
		for ip_obj in netw.hosts():
			ip = str(ip_obj)
			if ip in found_set or ip not in arp:
				continue
			found.append(ip)
			found_set.add(ip)

		# O IP do PROPRIO computador nunca aparece na tabela ARP do
		# sistema - ARP resolve o MAC de OUTROS hosts; a maquina local ja
		# sabe o proprio MAC direto da placa de rede, sem precisar
		# perguntar pra rede. Sem isso, o unico aparelho que deveria
		# SEMPRE ter MAC certo (o seu) ficaria sem, sempre - completa
		# aqui usando getmac.exe (get_mac_address, ja usado em outro
		# lugar do projeto), so pra esse IP especifico.
		try:
			iface_local = (net.get_ip_config(self._resolve_iface()) or {}).get("iface")
			if iface_local and lip and lip not in arp:
				mac_local = net.get_mac_address(iface_local)
				if mac_local:
					arp[lip] = mac_local.replace("-", ":").lower()
		except Exception:
			pass

		found.sort(key=lambda ip: tuple(int(p) for p in ip.split(".")))
		return found, arp

	def _oui_cache_path(self):
		"""Caminho do cache local da base COMPLETA de fabricantes (IEEE
		oui.csv, baixada sob demanda - ver _update_oui_database). Fica
		dentro da PASTA DE CONFIGURACAO da NVDA (globalVars.appArgs.
		configPath), nao na pasta de instalacao do addon - a de
		instalacao pode nao ter permissao de escrita, e o conteudo dela
		e apagado/substituido numa atualizacao do addon; a pasta de
		configuracao e onde a propria NVDA guarda os dados dela, sempre
		gravavel, e sobrevive a atualizacoes.

		Usar globalVars.appArgs.configPath (em vez de montar um caminho
		fixo tipo "%APPDATA%\\nvda") tambem funciona corretamente com
		instalacao portatil ou com --config-path customizado - a propria
		NVDA ja resolve isso, sem o addon precisar saber nome de usuario
		nem tipo de instalacao nenhum."""
		pasta = os.path.join(globalVars.appArgs.configPath, "networkTools")
		os.makedirs(pasta, exist_ok=True)
		return os.path.join(pasta, "oui_cache.csv")

	def _dns_list_path(self):
		"""Caminho do arquivo com a lista COMPLETA de servidores DNS que o
		usuario gerencia via "Gerenciar Servidores DNS" - mesma pasta de
		configuracao da NVDA que _oui_cache_path usa, pelo mesmo motivo
		(sobrevive a atualizacao do addon, sempre gravavel, funciona com
		instalacao portatil).

		Nome do arquivo (dns_servers.txt) e DIFERENTE do usado por uma
		versao anterior deste recurso (custom_dns.txt, quando a lista
		ainda era "so personalizados", separada da lista curada) de
		proposito: load_dns_list() so semeia com os padroes quando o
		arquivo NAO existe - um custom_dns.txt vazio deixado por essa
		versao anterior (confirmado ao vivo: usuario testou aquela
		versao, deixou vazio, e depois via a lista sempre vazia mesmo
		apos a fusao das duas listas) ficaria "existindo, mas vazio" pra
		sempre, e nunca seria semeado. Um nome de arquivo novo garante
		que a semeadura aconteca do zero, sem depender de detectar/migrar
		o arquivo antigo."""
		pasta = os.path.join(globalVars.appArgs.configPath, "networkTools")
		os.makedirs(pasta, exist_ok=True)
		return os.path.join(pasta, "dns_servers.txt")

	def _update_oui_database(self):
		"""Baixa a base COMPLETA de fabricantes por MAC da IEEE (~3 MB,
		~33 mil entradas) e guarda em cache local (ver _oui_cache_path).
		Acao explicita e separada de proposito - mesmo motivo dos
		Detalhes Adicionais Online que existiram antes: usa internet e
		baixa um arquivo de verdade, entao pede confirmacao e deixa claro
		o tamanho antes de fazer. Depois de baixada uma vez, a Varredura
		de Dispositivos passa a consultar essa base automaticamente (ver
		_scan) - nao precisa baixar de novo, a nao ser que queira
		atualizar pra pegar fabricantes registrados depois.

		DOWNLOAD CONDICIONAL: se a base local ja existir, o pedido leva
		a data da ultima vez que baixamos - o servidor da IEEE responde
		so "nao mudou nada" (sem reenviar os ~3 MB) se for o caso. Entao
		rodar isto de novo sem necessidade nao tem custo pesado nenhum -
		ver net.download_oui_database para o mecanismo completo.

		O cache fica na pasta de CONFIGURACAO da NVDA (ver
		_oui_cache_path), nao na pasta de instalacao do addon - por isso
		sobrevive normalmente a uma atualizacao do addon (que so
		substitui os arquivos da instalacao, nunca mexe na pasta de
		configuracao)."""
		existe, quando, n_atual = net.oui_database_info(self._oui_cache_path())
		if existe:
			data_txt = datetime.datetime.fromtimestamp(quando).strftime("%d/%m/%Y %H:%M")
			status_txt = _(
				"Já existe uma base local, baixada em {data}, com {n} fabricantes."
			).format(data=data_txt, n=n_atual)
		else:
			status_txt = _("Ainda não existe nenhuma base local baixada.")
		if not self._confirm(_("Atualizar Base de Fabricantes Completa"), status_txt + " " + _(
			"Vai verificar se há uma versão mais nova da base da IEEE "
			"(~3 MB) e baixar só se houver mudança. Precisa de internet. "
			"Continuar?"
		)):
			self._back()
			return
		ui.message(_("Verificando base de fabricantes, aguarde."))
		def worker():
			ok, atualizou, erro = net.download_oui_database(self._oui_cache_path())
			if ok and atualizou:
				_e, _q, n_novo = net.oui_database_info(self._oui_cache_path())
				wx.CallAfter(self._say, _(
					"Base de fabricantes atualizada com sucesso - {n} "
					"fabricantes disponíveis. A Varredura de Dispositivos já "
					"vai usar ela a partir de agora."
				).format(n=n_novo))
			elif ok and not atualizou:
				wx.CallAfter(self._say, _(
					"A base de fabricantes já estava atualizada - não foi "
					"necessário baixar de novo."
				))
			else:
				wx.CallAfter(self._say, _(
					"Não foi possível baixar a base de fabricantes ({erro})."
				).format(erro=erro))
		su.run_bg(worker)

	def _scan(self):
		ui.message(_("Varrendo rede local com ping, aguarde alguns segundos."))
		def worker():
			found, arp = self._discover_devices()
			if found is None:
				return
			if not found:
				wx.CallAfter(self._say, _("Nenhum dispositivo encontrado."))
				return
			oui_cache = self._oui_cache_path()
			lines = []
			for ip in found:
				mac = arp.get(ip)
				if mac:
					fabricante = net.mac_vendor(mac, oui_cache_path=oui_cache)
					if fabricante:
						lines.append(f"{ip}  ({mac} - {fabricante})")
					else:
						lines.append(f"{ip}  ({mac})")
				else:
					lines.append(ip)
			wx.CallAfter(self._show, _("Dispositivos na Rede"),
				_("Total: {n}").format(n=len(found)) + "\n\n" + "\n".join(lines))
		su.run_bg(worker)

	def _whois(self):
		# translators: titulo do dialogo que pede o IP a consultar
		ip = self._ask(_("Localizar IP"), _("IP para consultar:"))
		if not ip:
			self._back()
			return
		# Valida o formato antes de mandar para o servico externo: sem
		# isso, qualquer texto digitado (ou colado por engano) seria
		# embutido direto na URL de consulta. Nao e uma falha grave (e
		# so uma requisicao HTTP GET, sem execucao de codigo), mas
		# validar aqui evita erros confusos e deixa claro para o usuario
		# porque a consulta nao foi feita.
		try:
			ipaddress.ip_address(ip)
		except ValueError:
			ui.message(_("Endereço IP inválido: {ip}").format(ip=ip))
			self._back()
			return
		ui.message(_("Consultando {ip}, aguarde.").format(ip=ip))
		def cb(ok, body):
			if not ok:
				wx.CallAfter(self._say, _("Erro ao consultar {ip}.").format(ip=ip))
				return
			try:
				d = json.loads(body)
			except Exception:
				wx.CallAfter(self._say, _("Resposta inválida."))
				return
			if d.get("status") != "success":
				wx.CallAfter(self._say, _("IP {ip} não encontrado ou privado.").format(ip=ip))
				return
			wx.CallAfter(self._show, _("Whois - {ip}").format(ip=ip), su.fmt(
				(_("IP"),         d.get("query", ip)),
				(_("País"),       d.get("country","?")),
				(_("Estado"),     d.get("regionName","?")),
				(_("Cidade"),     d.get("city","?")),
				(_("Fuso horário"), d.get("timezone","?")),
				(_("Provedor"),   d.get("isp","?")),
				(_("Organização"), d.get("org","?")),
				(_("ASN"),        d.get("as","?")),
			))
		su.http_async(net.GEO_URL.format(ip=ip), cb)

	def _speedtest(self):
		# A escolha de tamanho, que antes era perguntada TODA vez via
		# MenuDialog, agora vem direto de Preferencias > Configuracoes >
		# Network Tools (padrao de fabrica: "medium") - o proposito de
		# expor esse valor nas Configuracoes e justamente parar de
		# perguntar de novo a cada execucao. Se o valor salvo nao bater
		# com nenhum preset conhecido (config corrompido, por exemplo),
		# cai no "medium" em vez de falhar.
		preset_id = config.conf["networkTools"]["speedtestDefaultSize"]
		down_bytes = up_bytes = None
		tamanhos = net.speedtest_sizes()
		for sid, _label, d_bytes, u_bytes in tamanhos:
			if sid == preset_id:
				down_bytes, up_bytes = d_bytes, u_bytes
				break
		if down_bytes is None:
			_sid, _label, down_bytes, up_bytes = tamanhos[1]
			preset_id = _sid
		# O preset "Grande" e pensado pra conexoes rapidas (1 Gbps ou
		# mais) - nessas, uma unica conexao TCP muitas vezes nao satura
		# o link sozinha (ver _speedtest_download_mbps em netinfo.py), e
		# o resultado sai mais baixo que a velocidade real contratada.
		# Varias conexoes em paralelo (quantidade configuravel em
		# Preferencias > Configuracoes, padrao 4) medem o throughput
		# agregado - a mesma tecnica que ferramentas profissionais de
		# teste de velocidade usam. Pequeno/Medio continuam com 1
		# conexao so - em links mais lentos isso ja satura sozinho, sem
		# ganho nenhum em complicar.
		conexoes = config.conf["networkTools"]["speedtestConnections"] if preset_id == "large" else 1
		# translators: mensagem falada enquanto o teste de velocidade roda em segundo plano
		ui.message(_("Testando velocidade da internet, isso pode levar alguns segundos."))
		def worker():
			result = net.internet_speed_test(down_bytes, up_bytes, connections=conexoes)
			latency_ms = result.get("latency_ms")
			download = result.get("download")
			upload = result.get("upload")
			if not download and not upload:
				# translators: mostra o motivo real da falha (ex.: erro de rede) em vez de so dizer que falhou, para dar uma pista do que investigar
				detalhe = result.get("download_error") or result.get("upload_error") or _("motivo desconhecido")
				wx.CallAfter(self._say, _(
					"Não foi possível medir a velocidade da internet ({detail})."
				).format(detail=detalhe))
				return
			latency_txt = _("{ms} ms").format(ms=latency_ms) if latency_ms is not None else _("sem resposta")
			download_txt = download or _("falhou ({detail})").format(detail=result.get("download_error") or _("motivo desconhecido"))
			upload_txt = upload or _("falhou ({detail})").format(detail=result.get("upload_error") or _("motivo desconhecido"))

			meta = result.get("meta") or {}
			loss = result.get("packet_loss_pct")
			jitter = result.get("jitter_ms")
			jitter_std = result.get("jitter_std_ms")
			loss_txt = _("{pct}%").format(pct=loss) if loss is not None else _("não foi possível medir")
			jitter_txt = (
				_("{j} ms (desvio padrão: {std} ms)").format(j=jitter, std=jitter_std)
				if jitter is not None else _("não foi possível medir")
			)

			linhas = [
				(_("Latência"),  latency_txt),
				(_("Download"),  download_txt),
				(_("Upload"),    upload_txt),
				# As duas linhas abaixo existem pra dar uma forma CONCRETA
				# de conferir que os parametros configurados (tamanho do
				# preset, conexoes paralelas) estao realmente sendo usados,
				# em vez de precisar adivinhar pela "sensacao" de rapido/
				# devagar - o volume total transferido muda de forma
				# visivel e calculavel quando "conexoes" muda (cada
				# conexao transfere o valor CHEIO configurado, nao
				# dividido - ver _speedtest_download_mbps em netinfo.py).
				(_("Dados solicitados no teste (download / upload)"), _("{down} MB / {up} MB").format(
					down=round((down_bytes * conexoes) / 1_000_000),
					up=round((up_bytes * conexoes) / 1_000_000))),
				(_("Conexões paralelas usadas"), str(conexoes)),
				(_("Perda de pacotes (20 pacotes para {host})").format(host="1.1.1.1"), loss_txt),
				(_("Jitter"),    jitter_txt),
			]
			# Se os metadados do Cloudflare falharem, mostra o MOTIVO real
			# numa unica linha em vez de deixar as tres linhas (IP/
			# protocolo/datacenter) simplesmente sumirem da tela sem
			# explicacao - "sumiu" parece bug; "falhou por X" e informacao
			# de verdade.
			if meta.get("ip"):
				linhas.append((_("IP público usado no teste"), meta.get("ip")))
				linhas.append((_("Protocolo"), meta.get("protocol")))
				linhas.append((_("Datacenter do teste"), meta.get("colo")))
			else:
				linhas.append((_("Metadados do Cloudflare"), _("não disponíveis ({detail})").format(
					detail=meta.get("error") or _("motivo desconhecido"))))

			# Diagnostico inteligente: velocidade de download/upload alta
			# sozinha nao garante uma conexao BOA pra tempo real (chamada
			# de voz/video, jogos online) - perda de pacotes ou jitter
			# elevados atrapalham isso mesmo com banda de sobra. Sem este
			# aviso, o usuario veria "88 Mbps" e presumiria que esta tudo
			# bem, sem saber que a conexao esta instavel por baixo.
			# Limiares: 25 Mbps ja e "rapido o bastante" pra qualquer uso
			# domestico comum (a instabilidade nao seria explicada por
			# falta de banda); jitter acima de 30 ms e perda acima de 1%
			# ja sao niveis que comecam a incomodar chamadas de voz/video
			# em tempo real, mesmo que o teste normal de velocidade nao
			# pegue isso.
			velocidade_alta = (result.get("download_mbps") or 0) >= 25
			jitter_alto = jitter is not None and jitter > 30
			perda_alta = loss is not None and loss > 1
			if velocidade_alta and (jitter_alto or perda_alta):
				motivos = []
				if perda_alta:
					motivos.append(_("perda de pacotes de {pct}%").format(pct=loss))
				if jitter_alto:
					motivos.append(_("jitter de {j} ms").format(j=jitter))
				linhas.append((_("Diagnóstico"), _(
					"Apesar da velocidade medida ser boa, sua conexão "
					"parece instável ({motivos}) - isso pode causar "
					"travamentos em chamadas de voz/vídeo e jogos "
					"online, mesmo com download/upload rápidos."
				).format(motivos=" e ".join(motivos))))

			wx.CallAfter(self._show, _("Teste de Velocidade da Internet"), su.fmt(*linhas))
		su.run_bg(worker)

	# --- Modulo C ---

	def _static_ip(self):
		if not su.is_admin():
			self._no_admin()
			return
		# Resolve a interface e le a configuracao ATUAL dela ANTES de abrir
		# o dialogo, pra pre-preencher os campos com o que a interface ja
		# tem agora (IP, mascara, gateway atuais) em vez de um exemplo fixo
		# sem relacao nenhuma com a rede de verdade do usuario - ver
		# StaticIPDialog em dialogs.py para o motivo completo.
		iface = self._resolve_iface() or net.active_iface()
		cfg_atual = net.get_ip_config(iface) if iface else None
		ip_atual = (cfg_atual or {}).get("ipv4") or ""
		mask_atual = (cfg_atual or {}).get("mask") or ""
		gw_atual = (cfg_atual or {}).get("gateway") or ""
		gui.mainFrame.prePopup()
		with dlg.StaticIPDialog(gui.mainFrame, ip_atual, mask_atual, gw_atual) as d:
			ret = d.ShowModal()
			ip, mask, gw = d.ip, d.mask, d.gateway
		gui.mainFrame.postPopup()
		if ret != wx.ID_OK:
			self._back()
			return
		# Valida os tres campos antes de rodar um comando com privilegio
		# de administrador. Nao evita nenhum ataque por si so (o netsh ja
		# recebe cada valor como argumento separado, sem shell, entao nao
		# ha risco de injecao de comando aqui) - mas evita aplicar uma
		# configuracao de rede claramente invalida e mostra um erro
		# imediato e claro em vez de deixar o netsh falhar de forma
		# confusa.
		for label, val in ((_("IP"), ip), (_("Máscara"), mask), (_("Gateway"), gw)):
			try:
				ipaddress.ip_address(val)
			except ValueError:
				ui.message(_("Valor inválido em {campo}: {valor}").format(campo=label, valor=val))
				self._back()
				return
		if not iface:
			ui.message(_("Interface não detectada."))
			self._back()
			return
		# Mesma ideia do _dhcp(): se o adaptador ja esta parado exatamente
		# neste IP/mascara/gateway em modo estatico, nao ha necessidade de
		# reaplicar - evita uma pequena interrupcao de rede a toa.
		d = net.get_ip_config(iface)
		if (d and d.get("iface") == iface and d.get("dhcp") is False
				and d.get("ipv4") == ip and d.get("mask") == mask and d.get("gateway") == gw):
			ui.message(_("Este adaptador já está configurado com este IP estático."))
			self._back()
			return
		ui.message(_("Aplicando {ip}, aguarde.").format(ip=ip))
		def cb(ok, out):
			if ok and ("Ok" in out or not out.strip()):
				wx.CallAfter(self._show, _("IP Estático OK"), su.fmt(
					(_("Interface"), iface), (_("IP"), ip), (_("Máscara"), mask), (_("Gateway"), gw)
				))
			else:
				wx.CallAfter(self._say, _("Erro: {detail}").format(detail=out.strip()[:150]))
		su.run_async(["netsh","interface","ip","set","address",
			f"name={iface}","source=static",f"addr={ip}",f"mask={mask}",f"gateway={gw}"], cb, 15)

	def _dhcp(self):
		if not su.is_admin():
			self._no_admin()
			return
		iface = self._resolve_iface() or net.active_iface()
		if not iface:
			ui.message(_("Interface não detectada."))
			self._back()
			return
		# Evita rodar o comando a toa quando o adaptador ja esta em DHCP -
		# nao causa dano (o comando e idempotente), mas gera uma pequena
		# renovacao de IP desnecessaria e uma confirmacao enganosa ("DHCP
		# OK") mesmo sem nenhuma mudanca real ter acontecido.
		d = net.get_ip_config(iface)
		if d and d.get("iface") == iface and d.get("dhcp") is True:
			ui.message(_("Este adaptador já está em modo dinâmico (DHCP)."))
			self._back()
			return
		ui.message(_("Revertendo para DHCP, aguarde."))
		def w():
			su.run(["netsh","interface","ip","set","address",f"name={iface}","source=dhcp"], 15)
			su.run(["netsh","interface","ip","set","dns",f"name={iface}","source=dhcp"], 15)
			wx.CallAfter(self._show, _("DHCP OK"), su.fmt((_("Interface"), iface), (_("Status"), _("IP dinâmico ativado"))))
		su.run_bg(w)

	def _flush_run(self, steps, title):
		"""Roda uma sequencia de comandos de reparo/limpeza (uma etapa
		unica ou varias em sequencia) e mostra o resultado de cada uma -
		OK/FALHA sempre pelo CODIGO DE RETORNO do comando, nunca pelo texto
		da saida (que vem traduzido). Reaproveitado por todos os itens do
		submenu de Reparo e Limpeza DNS, de uma etapa isolada ate o
		"Reparo Completo"."""
		if not su.is_admin():
			self._no_admin()
			return
		ui.message(_("Executando, aguarde."))
		def worker():
			lines = []
			for cmd, lbl in steps:
				ok, _out = su.run(cmd, 30)
				status = _("OK") if ok else _("FALHA")
				lines.append(f"{status}: {lbl}")
			wx.CallAfter(self._show, title, "\n".join(lines))
		su.run_bg(worker)

	def _flush_dns(self):
		self._flush_run(
			[(["ipconfig", "/flushdns"], _("Cache DNS limpo"))],
			_("Limpar Cache DNS"),
		)

	def _flush_register(self):
		self._flush_run(
			[(["ipconfig", "/registerdns"], _("DNS registrado novamente"))],
			_("Registrar DNS Novamente"),
		)

	def _flush_renew(self):
		# /release e /renew ficam sempre juntos, nunca como itens
		# separados: rodar so o /release deixaria o usuario sem IP nenhum
		# ate ele lembrar de rodar o /renew depois - juntar os dois evita
		# esse intervalo sem rede por acidente.
		#
		# IMPORTANTE: mira so na interface ativa (resolvida), em vez de
		# rodar "ipconfig /release"/"/renew" sem nome nenhum - sem
		# especificar, o ipconfig tenta renovar TODOS os adaptadores da
		# maquina de uma vez, inclusive os que nao tem nada a ver com a
		# conexao de verdade do usuario (ex.: uma porta Ethernet fisica
		# sem cabo plugado, ou um adaptador virtual do VirtualBox/Hyper-V)
		# - um desses falhando ("No se puede realizar ninguna operación
		# en Ethernet mientras los medios estén desconectados", confirmado
		# ao vivo no hardware do usuario) faz a operacao inteira aparecer
		# como FALHA, mesmo que a conexao que a pessoa realmente usa (ex.:
		# Wi-Fi) estivesse perfeitamente saudavel.
		iface = self._resolve_iface() or net.active_iface()
		if iface:
			passos = [
				(["ipconfig", "/release", iface], _("IP liberado")),
				(["ipconfig", "/renew", iface],   _("Novo IP solicitado")),
			]
		else:
			# Reserva: se nao foi possivel identificar nenhuma interface,
			# cai no comportamento antigo (todos os adaptadores) em vez de
			# simplesmente desistir.
			passos = [
				(["ipconfig", "/release"], _("IP liberado")),
				(["ipconfig", "/renew"],   _("Novo IP solicitado")),
			]
		self._flush_run(passos, _("Renovar IP"))

	def _flush_winsock(self):
		# Mais invasivo que limpar cache/renovar IP (mexe na pilha de
		# sockets inteira e normalmente so faz efeito completo depois de
		# reiniciar) - por isso pede confirmacao explicita antes, igual ao
		# padrao ja usado em outras acoes de maior risco do complemento.
		if not self._confirm(_("Resetar Pilha Winsock"), _(
			"Reseta a pilha de sockets do Windows - exige reiniciar o "
			"computador. Continuar?"
		)):
			self._back()
			return
		self._flush_run(
			[(["netsh", "winsock", "reset"], _("Pilha Winsock resetada (reinicie o computador)"))],
			_("Resetar Pilha Winsock"),
		)

	def _flush_tcpip(self):
		# O mais invasivo dos seis - reseta toda a configuracao de rede
		# para os padroes de fabrica do Windows. Mesma logica de
		# confirmacao explicita do reset de Winsock acima.
		if not self._confirm(_("Resetar Pilha TCP/IP"), _(
			"Reseta toda a configuração TCP/IP para os padrões de fábrica "
			"- exige reiniciar o computador. Continuar?"
		)):
			self._back()
			return
		self._flush_run(
			[(["netsh", "int", "ip", "reset"], _("Pilha TCP/IP resetada (reinicie o computador)"))],
			_("Resetar Pilha TCP/IP"),
		)

	def _flush_all(self):
		# Mesma sequencia de 4 passos que o antigo item unico "Reparo e
		# Limpeza DNS (Admin)" ja rodava, preservada aqui para quem so
		# quer o botao de sempre. De proposito NAO inclui os dois itens
		# novos (registrar DNS, resetar TCP/IP) - ver comentario em
		# _FLUSH_MENU.
		#
		# release/renew miram na interface ativa - mesmo motivo do
		# comentario em _flush_renew (evitar que um adaptador
		# desconectado/irrelevante derrube a operacao inteira).
		iface = self._resolve_iface() or net.active_iface()
		if iface:
			passo_release = (["ipconfig", "/release", iface], _("IP liberado"))
			passo_renew = (["ipconfig", "/renew", iface], _("Novo IP solicitado"))
		else:
			passo_release = (["ipconfig", "/release"], _("IP liberado"))
			passo_renew = (["ipconfig", "/renew"], _("Novo IP solicitado"))
		self._flush_run(
			[
				(["ipconfig", "/flushdns"],     _("Cache DNS limpo")),
				passo_release,
				passo_renew,
				(["netsh", "winsock", "reset"], _("Pilha resetada (reinicie o PC)")),
			],
			_("Reparo Completo"),
		)

	# --- Modulo D ---

	def _fmt_duration(self, seconds):
		"""Formata uma duracao em segundos como texto curto ("45 s",
		"2 min 5 s", "1 h 3 min") - usado nas mensagens de queda/retomada
		e no status do monitor. Sempre em numeros, entao nao precisa de
		plural/singular por idioma."""
		seconds = max(0, int(seconds))
		if seconds < 60:
			return _("{s} s").format(s=seconds)
		minutos, s = divmod(seconds, 60)
		if minutos < 60:
			return _("{m} min {s} s").format(m=minutos, s=s) if s else _("{m} min").format(m=minutos)
		horas, m = divmod(minutos, 60)
		return _("{h} h {m} min").format(h=horas, m=m) if m else _("{h} h").format(h=horas)

	@staticmethod
	def _jitter_stats(latencias):
		"""Calcula jitter e desvio padrao de uma lista de latencias (ms),
		reaproveitando EXATAMENTE a mesma definicao ja usada e testada em
		net.ping_parse() (Ping Inteligente) - assim os dois recursos do
		complemento falam a "mesma lingua" de jitter, em vez de duas
		metricas parecidas mas calculadas diferente:

		- jitter = media da variacao ABSOLUTA entre amostras
		  CONSECUTIVAS (a definicao classica de jitter de VoIP/RFC 3550 -
		  mais fiel a "trava a chamada" do que o desvio padrao sozinho,
		  porque pega variacao de UM PULO PRO OUTRO, nao dispersao geral)
		- desvio padrao (statistics.stdev) como medida complementar, mais
		  familiar pra quem ja conhece estatistica

		Devolve (jitter, std) ou (None, None) se houver menos de 2
		amostras (nao da pra medir variacao com uma unica leitura)."""
		if len(latencias) < 2:
			return None, None
		deltas = [abs(latencias[i] - latencias[i - 1]) for i in range(1, len(latencias))]
		jitter = sum(deltas) / len(deltas)
		std = statistics.stdev(latencias)
		return jitter, std

	def _monitor_toggle(self):
		if self._mon_on:
			if self._mon:
				self._mon_stop = True
			self._mon_on = False
			ui.message(_("Monitor desativado."))
			self._back()
			return
		self._monitor_start()
		self._back()

	def _monitor_start(self, announce=True):
		"""Liga o monitor de conexao. Reaproveitado tanto pelo item de
		menu (_monitor_toggle) quanto pelo auto-inicio na inicializacao do
		NVDA (ver __init__), quando "Iniciar o Monitor de Conexão
		automaticamente" esta marcado nas Configuracoes - por isso NAO
		chama self._back() aqui dentro (no auto-inicio nao ha menu nenhum
		aberto pra voltar) e aceita announce=False pra nao falar nada no
		meio da inicializacao do NVDA.

		net.get_ip_config() e list_interfaces() (dentro de
		_resolve_iface()) rodam um processo externo (netsh/ipconfig) e por
		isso SO acontecem dentro da thread de fundo, nunca aqui - rodar
		isso direto no __init__ travaria a inicializacao do NVDA ate o
		comando terminar.

		Sobem DUAS threads: loop() faz as verificacoes periodicas de
		sempre (DNS/internet + roteador, no intervalo configurado);
		watcher() fica bloqueada esperando o Windows avisar uma mudanca
		de rede de verdade (NotifyAddrChange, ver sysutils.py) e acorda a
		loop na hora, em vez de deixar a re-deteccao de rede esperar ate
		_MONITOR_REDETECT_SECONDS. As duas sao daemon (encerram sozinhas
		quando o NVDA fecha) e verificam self._mon_generation pra nunca
		mexer no estado de uma sessao do Monitor diferente da que as
		criou."""
		self._mon_start_ts = time.time()
		self._mon_stop = False
		# Zera as estatisticas por rede - so aqui, no LIGAR do Monitor
		# (nunca durante uma troca de rede em andamento, ver o loop
		# abaixo) - reiniciar o Monitor e a unica acao que apaga o
		# historico acumulado das redes visitadas.
		self._mon_networks = {}
		self._mon_current_network_id = None
		self._mon_generation += 1
		minha_geracao = self._mon_generation
		self._mon_wake = threading.Event()
		intervalo = config.conf["networkTools"]["monitorInterval"]

		def loop():
			# O alvo "externo" e o primeiro DNS configurado na interface
			# atual (mais relevante pro usuario que um IP fixo alheio a
			# configuracao dele) - 8.8.8.8 so entra como reserva quando nao
			# ha nenhum DNS detectado.
			def resolve_alvo():
				iface = self._resolve_iface()
				cfg = net.get_ip_config(iface) or {}
				dns_list = cfg.get("dns") or []
				return (dns_list[0] if dns_list else "8.8.8.8"), cfg.get("gateway"), cfg.get("iface")

			alvo0, gateway0, iface0 = resolve_alvo()
			net_id0, net_label0 = self._resolve_network_identity(iface0, gateway0)
			self._mon_current_network_id = net_id0
			self._get_or_create_network(net_id0, net_label0, alvo0, gateway0, iface0)
			proxima_deteccao = time.time() + _MONITOR_REDETECT_SECONDS
			was_up = None
			while not self._mon_stop:
				# --- deteccao de rede dinamica: se o usuario trocou de
				# Wi-Fi, plugou um cabo, ligou uma VPN etc., o alvo/gateway
				# resolvidos la no inicio da thread podem nao valer mais.
				# So confere de tempos em tempos (nao every ciclo), pra nao
				# dobrar as chamadas a netsh/ipconfig sem necessidade.
				agora_ts = time.time()
				if agora_ts >= proxima_deteccao:
					novo_alvo, novo_gateway, novo_iface_name = resolve_alvo()
					rede_agora = self._mon_networks[self._mon_current_network_id]
					# So considera troca de rede de VERDADE se os novos
					# valores forem validos (nao None/vazio) - quando o
					# sinal cai so por um instante (ex.: Wi-Fi reconectando
					# na MESMA rede apos perder o sinal), a interface pode
					# ficar sem IP/gateway/DNS momentaneamente, e
					# resolve_alvo() devolve None nesse meio-tempo. Sem essa
					# checagem, isso seria interpretado como "rede mudou" e
					# trocaria de estatisticas a toa - mesmo a rede
					# voltando a ser exatamente a mesma de antes.
					if novo_alvo and novo_gateway and (
							novo_alvo != rede_agora["target"] or novo_gateway != rede_agora["gateway"]
							or novo_iface_name != rede_agora["iface_name"]):
						# Troca de rede de verdade: identifica QUAL rede
						# (SSID ou MAC do gateway) e troca so o "ponteiro"
						# atual - se ja tiver visitado essa rede antes
						# nesta sessao, REAPROVEITA as estatisticas dela
						# (soma ao que ja tinha), em vez de comecar do
						# zero (decisao explicita: voltar pra uma rede ja
						# vista continua a MESMA contagem de antes).
						novo_net_id, novo_net_label = self._resolve_network_identity(
							novo_iface_name, novo_gateway)
						self._mon_current_network_id = novo_net_id
						rede_agora = self._get_or_create_network(
							novo_net_id, novo_net_label, novo_alvo, novo_gateway, novo_iface_name)
						wx.CallAfter(ui.message, _(
							"Rede alterada - agora monitorando {rede} ({target})."
						).format(rede=novo_net_label, target=novo_alvo))
					proxima_deteccao = agora_ts + _MONITOR_REDETECT_SECONDS

				rede = self._mon_networks[self._mon_current_network_id]

				# --- latencia do roteador (rede local) - roda TODO ciclo
				# agora, nao so quando o alvo externo falha, pra dar uma
				# media de verdade (nao so um "local"/"internet" no momento
				# da queda). Prioriza IcmpSendEcho nativo (sem processo
				# novo, ver sysutils.py) - so cai pro ping.exe de sempre se
				# a API nativa nao estiver disponivel nesse Windows.
				gw_up = None
				gw_latencia_ms = None
				if rede["gateway"]:
					if su.icmp_available():
						rtt = su.icmp_ping(rede["gateway"], timeout_ms=1000)
						gw_up = rtt is not None
						if gw_up:
							gw_latencia_ms = float(rtt)
							rede["gw_latencies"].append(gw_latencia_ms)
					else:
						rc, gw_out = su.run_rc(
							["ping", "-n", "1", "-w", "1000", rede["gateway"]], timeout=3)
						gw_up = (rc == 0)
						if gw_up:
							m = rx.RX_PING_AVG.search(gw_out)
							if m:
								gw_latencia_ms = float(m.group(1))
								rede["gw_latencies"].append(gw_latencia_ms)
				rede["last_gw_latency_ms"] = gw_latencia_ms

				# --- checagem externa (DNS/internet) ---
				inicio = time.perf_counter()
				try:
					with socket.create_connection((rede["target"], 53), timeout=3):
						up = True
				except OSError:
					up = False
				latencia_ms = (time.perf_counter() - inicio) * 1000
				agora = time.time()
				rede["last_check_ts"] = agora
				rede["total_checks"] += 1
				if up:
					rede["last_latency_ms"] = latencia_ms
					rede["last_scope"] = None
					rede["latencies"].append(latencia_ms)
				else:
					rede["last_latency_ms"] = None
					if rede["gateway"]:
						rede["last_scope"] = "local" if not gw_up else "internet"
					else:
						rede["last_scope"] = None

				if was_up is False and up:
					dur = self._fmt_duration(agora - rede["down_since"]) if rede["down_since"] else None
					if rede["down_since"]:
						rede["total_down_seconds"] += agora - rede["down_since"]
					rede["down_since"] = None
					if dur:
						wx.CallAfter(ui.message, _(
							"Conexão restabelecida após {dur} sem conexão."
						).format(dur=dur))
					else:
						wx.CallAfter(ui.message, _("Conexão restabelecida."))
				elif was_up is True and not up:
					rede["drop_count"] += 1
					rede["down_since"] = agora
					if rede["last_scope"] == "local":
						msg = _(
							"Atenção: conexão perdida - o roteador também não "
							"está respondendo (parece ser um problema na rede local)."
						)
					else:
						msg = _("Atenção: conexão de rede perdida.")
					wx.CallAfter(ui.message, msg)
				elif was_up is None and not up:
					rede["drop_count"] += 1
					rede["down_since"] = agora
					if rede["last_scope"] == "local":
						msg = _(
							"Aviso: sem conexão no momento - o roteador também "
							"não está respondendo (parece ser um problema na rede local)."
						)
					else:
						msg = _("Aviso: sem conexão no momento.")
					wx.CallAfter(ui.message, msg)
				was_up = up
				# Event.wait(intervalo) se comporta como time.sleep(intervalo)
				# quando ninguem acorda a thread antes da hora (devolve False
				# no timeout, igual sempre foi) - a diferenca e que a thread
				# vigia (ver watcher() abaixo) pode chamar mon_wake.set() ANTES
				# do timeout, assim que o Windows avisar uma mudanca de rede de
				# verdade, acordando o loop na hora em vez de esperar ate 60s
				# pela proxima janela de re-deteccao periodica.
				acordou_por_evento = self._mon_wake.wait(timeout=intervalo)
				self._mon_wake.clear()
				if acordou_por_evento:
					proxima_deteccao = 0  # forca a re-deteccao logo no topo do proximo ciclo

		def watcher():
			# Fica bloqueada em wait_for_network_change() (NotifyAddrChange,
			# ver sysutils.py) ate o Windows reportar uma mudanca de rede de
			# verdade, e acorda o loop principal na hora atraves do Event -
			# so existe pra isso, nao mexe em nenhum outro estado do monitor
			# diretamente. minha_geracao evita que uma vigia "orfa" de uma
			# sessao anterior do Monitor mexa na sessao atual (ver comentario
			# em self._mon_generation, no __init__).
			while not self._mon_stop and self._mon_generation == minha_geracao:
				mudou = su.wait_for_network_change()
				if self._mon_stop or self._mon_generation != minha_geracao:
					return
				if mudou:
					self._mon_wake.set()
				else:
					# NotifyAddrChange falhou (ambiente sem a DLL, por
					# exemplo) - desiste silenciosamente em vez de girar
					# num loop apertado tentando de novo sem parar. A
					# sondagem periodica de 60s continua funcionando
					# normalmente como rede de seguranca.
					return

		self._mon = threading.Thread(target=loop, daemon=True)
		self._mon.start()
		threading.Thread(target=watcher, daemon=True).start()
		self._mon_on = True
		if announce:
			ui.message(_("Monitor ativado. NVDA avisará sobre quedas de rede."))

	def _format_network_status_lines(self, rede):
		"""Monta as linhas de status de UMA rede especifica (usado por
		_monitor_status para gerar o conteudo de cada aba) - a mesma
		logica que existia antes, so que lendo de um dict de rede em vez
		de variaveis unicas do monitor inteiro."""
		agora = time.time()
		if rede["down_since"]:
			estado = _("Sem conexão há {dur}").format(dur=self._fmt_duration(agora - rede["down_since"]))
			if rede["last_scope"] == "local":
				estado += " — " + _("o roteador também não está respondendo (problema na rede local)")
		elif rede["last_latency_ms"] is not None:
			estado = _("Conectado ({ms} ms de latência do DNS/internet na última verificação)").format(
				ms=round(rede["last_latency_ms"]))
		else:
			estado = _("Aguardando a primeira verificação...")
		if rede["last_check_ts"]:
			ultima = _("há {dur}").format(dur=self._fmt_duration(agora - rede["last_check_ts"]))
		else:
			ultima = _("ainda não verificou")

		# Tempo sem conexao NESTA REDE inclui a queda ATUAL em andamento
		# (se houver), somada ao que ja foi acumulado nas quedas
		# anteriores DESTA MESMA REDE - por isso soma total_down_seconds
		# com o trecho da queda em curso, em vez de usar so um dos dois.
		# A disponibilidade e calculada desde a PRIMEIRA vez que esta
		# rede foi vista nesta sessao (first_seen_ts), nao desde que o
		# Monitor ligou - se o Monitor comecou numa rede diferente e so
		# trocou pra esta depois, o tempo "ligado" dessa rede especifica
		# comeca so quando ela realmente entrou em cena.
		queda_atual = (agora - rede["down_since"]) if rede["down_since"] else 0
		tempo_sem_conexao = rede["total_down_seconds"] + queda_atual
		tempo_monitorada = agora - rede["first_seen_ts"]
		disponibilidade = (
			max(0.0, (tempo_monitorada - tempo_sem_conexao) / tempo_monitorada * 100)
			if tempo_monitorada > 0 else 100.0
		)

		if rede["latencies"]:
			media = sum(rede["latencies"]) / len(rede["latencies"])
			latencia_media = _("{ms} ms").format(ms=round(media))
			latencia_min_max = _("{min} ms / {max} ms").format(
				min=round(min(rede["latencies"])), max=round(max(rede["latencies"])))
		else:
			latencia_media = _("sem dados ainda")
			latencia_min_max = _("sem dados ainda")

		nome_iface = rede["iface_name"] or _("adaptador de rede")
		if rede["gw_latencies"]:
			gw_media = sum(rede["gw_latencies"]) / len(rede["gw_latencies"])
			gw_latencia_media = _("{ms} ms").format(ms=round(gw_media))
			gw_latencia_min_max = _("{min} ms / {max} ms").format(
				min=round(min(rede["gw_latencies"])), max=round(max(rede["gw_latencies"])))
		elif not rede["gateway"]:
			gw_latencia_media = gw_latencia_min_max = _("roteador não detectado")
		else:
			gw_latencia_media = gw_latencia_min_max = _("sem dados ainda")

		# Jitter (variacao de latencia entre uma verificacao e a proxima)
		# e o que costuma causar "travadas" em chamada de voz/video, mais
		# do que a latencia media sozinha - uma conexao com 150 ms
		# ESTAVEIS costuma incomodar menos que uma com 40 ms que varia
		# entre 10 e 200. Mesma definicao usada na Ping Inteligente (ver
		# _jitter_stats).
		jitter_dns, std_dns = self._jitter_stats(rede["latencies"])
		jitter_dns_txt = _("{j} ms (desvio padrão: {std} ms)").format(
			j=round(jitter_dns, 1), std=round(std_dns, 1)) if jitter_dns is not None else _("sem dados ainda")
		jitter_gw, std_gw = self._jitter_stats(rede["gw_latencies"])
		jitter_gw_txt = _("{j} ms (desvio padrão: {std} ms)").format(
			j=round(jitter_gw, 1), std=round(std_gw, 1)) if jitter_gw is not None else _("sem dados ainda")

		return [
			(_("Conexão"),                       estado),
			(_("Última verificação"),            ultima),
			(_("Monitorando esta rede há"),      self._fmt_duration(tempo_monitorada)),
			(_("Latência média ({iface} - roteador)").format(iface=nome_iface),      gw_latencia_media),
			(_("Latência mínima / máxima ({iface})").format(iface=nome_iface),       gw_latencia_min_max),
			(_("Jitter ({iface})").format(iface=nome_iface),                         jitter_gw_txt),
			(_("Latência média (DNS/internet)"),                   latencia_media),
			(_("Latência mínima / máxima (DNS/internet)"),         latencia_min_max),
			(_("Jitter (DNS/internet)"),                           jitter_dns_txt),
			(_("Disponibilidade nesta rede"),    _("{pct}%").format(pct=round(disponibilidade, 1))),
			(_("Tempo total sem conexão"),       self._fmt_duration(tempo_sem_conexao)),
			(_("Verificações realizadas"),       str(rede["total_checks"])),
			(_("Servidor testado (internet)"),   rede["target"] or _("não definido")),
			(_("Roteador testado (rede local)"), rede["gateway"] or _("não detectado")),
			(_("Quedas nesta rede"),             str(rede["drop_count"])),
		]

	def _monitor_status(self):
		"""Consulta o estado atual do monitor sem ligar nem desligar nada.
		Mostra uma ABA POR REDE visitada nesta sessao (SSID do Wi-Fi, ou
		MAC do gateway para Ethernet - ver _resolve_network_identity) -
		cada rede acumula suas proprias estatisticas (latencia, quedas,
		disponibilidade), sem misturar com as de outra rede diferente
		visitada na mesma sessao. A aba da rede ATUAL vem primeiro,
		marcada como tal; as outras seguem na ordem em que foram
		visitadas."""
		if not self._mon_on:
			self._say(_("O monitor de conexão está desligado no momento."))
			return
		if not self._mon_networks:
			self._say(_("Monitor ativo, ainda aguardando a primeira verificação."))
			return
		agora = time.time()
		ligado_ha = self._fmt_duration(agora - self._mon_start_ts) if self._mon_start_ts else _("desconhecido")
		cabecalho = _("Monitor ativo (ligado há {dur} no total). {n} rede(s) visitada(s) nesta sessão.").format(
			dur=ligado_ha, n=len(self._mon_networks))

		abas = []
		# A rede ATUAL vai primeiro, sempre - e a informacao mais
		# relevante agora, entao nao faz sentido obrigar a navegar por
		# outras abas pra chegar nela. As demais seguem na ordem em que
		# foram visitadas nesta sessao.
		ids_ordenados = [self._mon_current_network_id] + [
			nid for nid in self._mon_networks if nid != self._mon_current_network_id
		]
		for net_id in ids_ordenados:
			rede = self._mon_networks[net_id]
			linhas = self._format_network_status_lines(rede)
			if net_id == self._mon_current_network_id:
				# translators: rotulo da aba da rede ATUALMENTE ativa no Monitor de Conexao - {rede} e o nome/SSID da rede
				rotulo = _("{rede} (atual)").format(rede=rede["label"])
			else:
				rotulo = rede["label"]
			conteudo = cabecalho + "\n\n" + su.fmt(*linhas)
			abas.append((rotulo, conteudo))
		self._show_tabs(_("Status do Monitor de Conexão"), abas)

	def _confirm(self, title, message):
		"""Confirmacao extra (Sim/Nao), usada so onde uma acao aumenta o
		risco de exposicao da maquina (abrir porta) - diferente do padrao
		"requer Administrador" ja usado em todo o resto do complemento, que
		so impede execucao acidental sem privilegio, nao pede confirmacao
		de intencao."""
		gui.mainFrame.prePopup()
		box = wx.MessageDialog(gui.mainFrame, message, title, wx.YES_NO | wx.ICON_WARNING)
		ret = box.ShowModal()
		box.Destroy()
		gui.mainFrame.postPopup()
		return ret == wx.ID_YES

	def _valida_porta(self, porta):
		return porta.isdigit() and 1 <= int(porta) <= 65535

	def _host_seguro(self, host):
		"""Recusa um endereco/host digitado pelo usuario que comece com
		"-" antes de virar argumento de linha de comando pro ping.exe/
		tracert.exe. Nao ha risco de injecao de COMANDO aqui (todo
		subprocesso deste addon roda com uma lista de argumentos, nunca
		via shell - ver su.run/run_rc), mas uma string assim ainda
		poderia ser confundida pela PROPRIA ferramenta nativa como uma
		das flags DELA (ex.: um host "-t" faria o ping.exe pingar
		continuamente em vez de ser tratado como hostname invalido,
		ignorando o "-n 1" que a gente pediu). Devolve True se for
		seguro passar adiante, False se devesse ser recusado."""
		return not host.startswith("-")

	# --- Modulo E (Firewall) ---

	def _fw_listen(self):
		ui.message(_("Consultando portas em escuta, aguarde."))
		def worker():
			itens = fw.list_listening_ports()
			if not itens:
				wx.CallAfter(self._say, _("Nenhuma porta em escuta encontrada."))
				return
			linhas = [
				_("{proto} {porta} — processo: {proc} (PID {pid})").format(
					proto=it["protocolo"], porta=it["porta"], proc=it["processo"], pid=it["pid"])
				for it in itens
			]
			txt = _("Total: {n} portas em escuta").format(n=len(itens)) + "\n\n" + "\n".join(linhas)
			wx.CallAfter(self._show, _("Portas em Escuta"), txt)
		su.run_bg(worker)

	def _fw_rules(self):
		ui.message(_("Consultando regras de firewall ativas, aguarde."))
		def worker():
			entrada = fw.list_active_rules("in")
			saida = fw.list_active_rules("out")
			if not entrada and not saida:
				wx.CallAfter(self._say, _("Nenhuma regra de firewall ativa encontrada."))
				return
			def _texto(regras, msg_vazio):
				if not regras:
					return msg_vazio
				blocos = [su.fmt(
					(_("Nome"),        r.get("nome")),
					(_("Perfis"),      r.get("profiles")),
					(_("Protocolo"),   r.get("protocol")),
					(_("Porta local"), r.get("localport")),
					(_("Ação"),        r.get("action")),
				) for r in regras]
				return "\n\n".join(blocos)
			tabs = [
				(_("Entrada ({n})").format(n=len(entrada)),
					_texto(entrada, _("Nenhuma regra de entrada ativa."))),
				(_("Saída ({n})").format(n=len(saida)),
					_texto(saida, _("Nenhuma regra de saída ativa."))),
			]
			ui.message(_("Total: {n} regras ativas ({entrada} de entrada, {saida} de saída)").format(
				n=len(entrada) + len(saida), entrada=len(entrada), saida=len(saida)))
			wx.CallAfter(self._show_tabs, _("Regras de Firewall Ativas"), tabs)
		su.run_bg(worker)

	def _fw_create(self):
		if not su.is_admin():
			self._no_admin()
			return
		gui.mainFrame.prePopup()
		with dlg.FirewallRuleDialog(gui.mainFrame, _("Criar Regra de Firewall")) as d:
			ret = d.ShowModal()
			tipo, direcao_idx = d.tipo, d.direcao
			porta, protocolo = d.porta, d.protocolo
			programa, ip_remoto = d.programa, d.ip_remoto
			acao_idx = d.acao
			pd, pp, ppub = d.perfil_dominio, d.perfil_privado, d.perfil_publico
			nome, descricao = d.nome, d.descricao
		gui.mainFrame.postPopup()
		if ret != wx.ID_OK:
			self._back()
			return

		direcao = "out" if direcao_idx == 1 else "in"
		acao = "block" if acao_idx == 1 else "allow"
		usa_programa = (tipo == 1)

		if usa_programa:
			if not programa:
				ui.message(_("Informe o caminho do programa."))
				self._back()
				return
			protocolo_final, porta_final = None, None
		else:
			if not self._valida_porta(porta):
				ui.message(_("Porta inválida: {porta}").format(porta=porta))
				self._back()
				return
			protocolo_final, porta_final = protocolo, porta
			programa = None

		perfis_legiveis = []
		perfis_chaves = []
		if pd:
			perfis_legiveis.append(_("Domínio")); perfis_chaves.append("domain")
		if pp:
			perfis_legiveis.append(_("Privado")); perfis_chaves.append("private")
		if ppub:
			perfis_legiveis.append(_("Público")); perfis_chaves.append("public")
		# Se nenhum perfil for marcado, nao restringe (todos os perfis) - e
		# mais seguro do que criar silenciosamente uma regra que nao vale
		# para perfil nenhum sem o usuario perceber.
		perfis_final = perfis_chaves or None
		perfis_txt = ", ".join(perfis_legiveis) if perfis_legiveis else _("Todos")

		if not nome:
			nome = fw.sugerir_nome_regra(direcao, acao, protocolo=protocolo_final,
				porta=porta_final, programa=programa)

		# Confirmacao extra so quando a acao de fato AUMENTA a exposicao da
		# maquina (permitir entrada) - mesmo criterio ja usado antes so
		# para "Abrir Porta".
		if direcao == "in" and acao == "allow":
			alvo = programa if usa_programa else f"{porta_final}/{protocolo_final}"
			if not self._confirm(
				_("Confirmar Regra de Entrada"),
				_(
					"Permite conexões de ENTRADA em {alvo}, vindas de "
					"{escopo}, até remover a regra depois. Continuar?"
				).format(alvo=alvo, escopo=ip_remoto if ip_remoto else _("QUALQUER endereço"))
			):
				self._back()
				return

		ui.message(_("Criando regra de firewall, aguarde."))
		def worker():
			rc, out, nome_criado = fw.add_custom_rule(
				nome, direcao, acao, protocolo=protocolo_final, porta=porta_final,
				programa=programa, ip_remoto=ip_remoto or None,
				perfis=perfis_final, descricao=descricao or None,
			)
			if rc == 0:
				linhas = [
					(_("Regra"),     nome_criado),
					(_("Direção"),   _("Entrada") if direcao == "in" else _("Saída")),
					(_("Ação"),      _("Permitir") if acao == "allow" else _("Bloquear")),
				]
				if usa_programa:
					linhas.append((_("Programa"), programa))
				else:
					linhas.append((_("Porta"), f"{porta_final}/{protocolo_final}"))
				if ip_remoto:
					linhas.append((_("IP remoto"), ip_remoto))
				linhas.append((_("Perfis"), perfis_txt))
				linhas.append((_("Status"), _("Regra criada com sucesso")))
				wx.CallAfter(self._show, _("Regra de Firewall Criada"), su.fmt(*linhas))
			else:
				wx.CallAfter(self._say, _("Erro ao criar a regra: {detail}").format(detail=(out or "").strip()[:150]))
		su.run_bg(worker)

	def _fw_remove(self):
		if not su.is_admin():
			self._no_admin()
			return
		ui.message(_(
			"Consultando todas as regras de firewall, aguarde. Isso inclui "
			"as regras padrão do Windows, então pode demorar um pouco."
		))
		def worker():
			regras = fw.list_removable_rules()
			wx.CallAfter(self._fw_remove_pick, regras)
		su.run_bg(worker)

	def _fw_remove_pick(self, regras):
		if not regras:
			self._say(_("Nenhuma regra de firewall foi encontrada."))
			return
		itens = []
		for i, r in enumerate(regras):
			direcao_txt = _("Entrada") if r["direcao"] == "in" else _("Saída")
			rotulo = _("{nome} — {direcao}").format(nome=r["nome"], direcao=direcao_txt)
			itens.append((str(i), rotulo))
		gui.mainFrame.prePopup()
		with dlg.MenuDialog(gui.mainFrame, _("Selecionar Regra para Remover"), itens) as d:
			ret = d.ShowModal()
			chosen = d.chosen
		gui.mainFrame.postPopup()
		if ret != wx.ID_OK or chosen is None:
			self._back()
			return
		regra = regras[int(chosen)]
		nome, direcao = regra["nome"], regra["direcao"]
		if not nome.startswith(fw.RULE_PREFIX):
			# Regra que NAO foi criada pelo Network Tools - pode ser do
			# Windows ou de outro programa. Remover isto pode afetar esse
			# programa ou uma excecao padrao do sistema - por isso, uma
			# confirmacao extra, so para este caso.
			direcao_txt = _("Entrada") if direcao == "in" else _("Saída")
			if not self._confirm(
				_("Confirmar Remoção de Regra do Sistema"),
				_(
					"A regra \"{nome}\" ({direcao}) não foi criada pelo "
					"Network Tools - removê-la pode afetar outro programa "
					"ou uma exceção do sistema. Continuar mesmo assim?"
				).format(nome=nome, direcao=direcao_txt)
			):
				self._back()
				return
		ui.message(_("Removendo regra, aguarde."))
		def worker2():
			rc, out = fw.delete_rule(nome, direcao)
			if rc == 0:
				wx.CallAfter(self._say, _("Regra removida: {nome}").format(nome=nome))
			else:
				wx.CallAfter(self._say, _("Erro ao remover a regra: {detail}").format(detail=(out or "").strip()[:150]))
		su.run_bg(worker2)

	def _fw_profiles(self):
		ui.message(_("Consultando status do firewall, aguarde."))
		def worker():
			perfis = fw.firewall_profiles_state()
			if not perfis:
				wx.CallAfter(self._say, _("Não foi possível consultar o status do firewall."))
				return
			linhas = [
				_("{perfil}: {status}").format(
					perfil=p["perfil"],
					status=_("Ligado") if p["ligado"] else _("Desligado"),
				) for p in perfis
			]
			wx.CallAfter(self._show, _("Status do Firewall por Perfil"), "\n".join(linhas))
		su.run_bg(worker)

	def _fw_local_test(self):
		gui.mainFrame.prePopup()
		with dlg.FirewallPortDialog(gui.mainFrame, _("Testar Porta Localmente")) as d:
			ret = d.ShowModal()
			porta, protocolo = d.porta, d.protocolo
		gui.mainFrame.postPopup()
		if ret != wx.ID_OK:
			self._back()
			return
		if not self._valida_porta(porta):
			ui.message(_("Porta inválida: {porta}").format(porta=porta))
			self._back()
			return
		ui.message(_("Testando a porta {porta}/{protocolo} localmente, aguarde.").format(porta=porta, protocolo=protocolo))
		def worker():
			r = fw.test_port_local(protocolo, porta)
			linhas = [
				(_("Porta"),                      f"{porta}/{protocolo}"),
				(_("Algo escutando agora"),        _("Sim") if r["escutando"] else _("Não")),
			]
			if r["escutando"]:
				linhas.append((_("Processo"), _("{proc} (PID {pid})").format(proc=r["processo"], pid=r["pid"])))
			linhas.append((
				_("Regra de firewall permitindo"),
				_("Sim") if r["regra_permite"] else _("Não encontrada"),
			))
			if r["regra_permite"]:
				linhas.append((_("Nome da regra"), r["regra_nome"]))
				linhas.append((
					_("Tipo de regra"),
					_("Específica desta porta") if r["regra_especifica"]
					else _("Genérica de programa (libera qualquer porta)"),
				))
			if r["conexao_local_ok"] is not None:
				linhas.append((
					_("Conexão local de teste"),
					_("Bem-sucedida") if r["conexao_local_ok"] else _("Falhou"),
				))
			if r["porta_comumente_bloqueada_pelo_provedor"]:
				# translators: aviso mostrado quando a porta testada esta entre
				# as que provedores de internet costumam bloquear por padrao,
				# mesmo que o teste local mostre resultado positivo
				linhas.append((_("Aviso"), _(
					"A porta {porta} está entre as que a maioria dos "
					"provedores de internet bloqueia por padrão, "
					"independente de qualquer configuração sua. Mesmo um "
					"resultado local positivo aqui não garante acesso "
					"vindo de fora da sua rede."
				).format(porta=porta)))
			wx.CallAfter(self._show, _("Teste de Porta Local"), su.fmt(*linhas))
		su.run_bg(worker)

	# --- Modulo F (Diagnostico Avancado - PowerShell) ---

	def _psh_adapter(self):
		"""Diagnostico detalhado de UM adaptador via PowerShell - MTU,
		metrica de rota, contadores de erro/descarte de pacotes. Ver
		networkToolsLib/pshell.py para o porque de isolar isso do resto,
		que usa so netsh."""
		ui.message(_(
			"Consultando diagnóstico avançado via PowerShell, aguarde "
			"(pode levar alguns segundos na primeira vez)."
		))
		def worker():
			iface = self._resolve_iface() or net.active_iface()
			if not iface:
				wx.CallAfter(self._say, _("Interface não detectada."))
				return
			dados = psh.adapter_rich_diagnostics(iface)
			if dados is None:
				wx.CallAfter(self._say, _(
					"Não foi possível obter o diagnóstico avançado. O "
					"PowerShell pode não estar disponível neste computador "
					"(às vezes bloqueado por política do sistema) ou a "
					"consulta falhou. O restante do Network Tools continua "
					"funcionando normalmente sem ele."
				))
				return
			# DNS Servers vem como lista, misturando IPv4/IPv6 sem ordem -
			# agrupa IPv4 primeiro (mais lido no dia a dia), depois IPv6,
			# preservando a ordem relativa DENTRO de cada grupo (e a
			# preferencia primario/secundario que o Windows ja reportou).
			# Cada servidor em sua PROPRIA linha (rotulo "Servidor N",
			# mesmo padrao ja usado em "Ver Servidores DNS Atuais") - uma
			# linha so com tudo separado por virgula lia mal no NVDA e
			# misturava os enderecos visualmente.
			dns_servers = dados.get("DNSServers") or []
			dns_ipv4 = [s for s in dns_servers if ":" not in s]
			dns_ipv6 = [s for s in dns_servers if ":" in s]
			dns_ordenados = dns_ipv4 + dns_ipv6
			dns_linhas = (
				[(_("Servidor {n}").format(n=i + 1), ip) for i, ip in enumerate(dns_ordenados)]
				if dns_ordenados else [(_("Servidores DNS"), _("não disponível"))]
			)

			linhas = [
				(_("Interface"),              dados.get("InterfaceAlias") or iface),
				(_("Descrição do adaptador"), dados.get("InterfaceDescription") or _("não disponível")),
				(_("Endereço IPv4"),          dados.get("IPv4Address") or _("não disponível")),
				(_("Gateway"),                dados.get("IPv4Gateway") or _("não disponível")),
				*dns_linhas,
				(_("MTU"),                    str(dados.get("Mtu")) if dados.get("Mtu") is not None else _("não disponível")),
				(_("Métrica de rota"),        str(dados.get("InterfaceMetric")) if dados.get("InterfaceMetric") is not None else _("não disponível")),
				(_("Estado da conexão"),      dados.get("ConnectionState") or _("não disponível")),
				(_("Bytes recebidos"),        str(dados.get("ReceivedBytes")) if dados.get("ReceivedBytes") is not None else _("não disponível")),
				(_("Bytes enviados"),         str(dados.get("SentBytes")) if dados.get("SentBytes") is not None else _("não disponível")),
				(_("Pacotes recebidos descartados"), str(dados.get("ReceivedDiscardedPackets") or 0)),
				(_("Pacotes recebidos com erro"),    str(dados.get("ReceivedPacketErrors") or 0)),
				(_("Pacotes enviados descartados"),  str(dados.get("OutboundDiscardedPackets") or 0)),
				(_("Pacotes enviados com erro"),     str(dados.get("OutboundPacketErrors") or 0)),
			]
			wx.CallAfter(self._show, _("Diagnóstico Avançado do Adaptador"), su.fmt(*linhas))
		su.run_bg(worker)

	def terminate(self):
		self._mon_stop = True
		if NetworkToolsSettingsPanel in NVDASettingsDialog.categoryClasses:
			NVDASettingsDialog.categoryClasses.remove(NetworkToolsSettingsPanel)
		super().terminate()
