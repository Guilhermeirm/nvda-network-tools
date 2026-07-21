# -*- coding: utf-8 -*-
# Expressoes regulares usadas para interpretar a saida de comandos do
# Windows (netsh, ipconfig, nslookup, tracert, arp etc.) em varios
# idiomas do sistema operacional.
#
# IMPORTANTE: isto NAO tem relacao com o idioma da interface do
# complemento (isso e tratado via gettext em outro lugar). Aqui cobrimos
# os idiomas em que o proprio WINDOWS pode estar configurado - ou seja,
# o texto que "ipconfig", "netsh" etc. imprimem no terminal - para que os
# dados sejam lidos corretamente nao importa o idioma do sistema.

import re


def _label_alt(*labels):
	"""Monta o fragmento de alternancia "(?:rotulo1|rotulo2|...)" a partir
	de uma lista de variantes de rotulo (uma por idioma do Windows
	suportado). Existe so para deixar cada regex mais facil de ler e
	editar: em vez de uma unica string longa concatenada por "|", cada
	variante de idioma vira um item de lista separado - adicionar,
	remover ou revisar um idioma fica um diff de uma linha, sem precisar
	reler a expressao inteira para nao quebrar a pontuacao.
	"""
	return "(?:" + "|".join(labels) + ")"


IP = r"([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})"

# --- ipconfig /all (reserva de texto, usado so se o netsh nao bastar) ---
RX_IPV4 = re.compile(
	_label_alt(r"Direcci[oó]n\s+IPv4", r"IPv4\s+Address", r"Endere.{1,5}o\s+IPv4")
	+ r".{0,50}:\s*" + IP, re.I)
RX_MASK = re.compile(
	_label_alt(r"M[aá]scara\s+de\s+subred", r"Subnet\s+Mask", r"M.{1,5}scara\s+de\s+Sub")
	+ r".{0,50}:\s*" + IP, re.I)
RX_GW = re.compile(
	_label_alt(r"Puerta\s+de\s+enlace", r"Default\s+Gateway", r"Gateway\s+Padr")
	+ r".{0,50}:\s*" + IP, re.I)
RX_DNS = re.compile(
	_label_alt(r"Servidores\s+DNS", r"DNS\s+Servers?") + r".{0,50}:\s*" + IP, re.I)
RX_DNS2 = re.compile(r"^\s{5,}" + IP + r"\s*$", re.M)
RX_DISC = re.compile(
	_label_alt(r"M[ií]dia\s+desconectada", r"Media\s+desconect",
		r"Media\s+disconnected", r"medios\s+descon"), re.I)
RX_IFACE = re.compile(
	# \b no inicio e essencial: sem ele, "Desconectado" (PT/ES),
	# "Disconnected" (EN) e "Déconnecté" (FR) batem como "conectado" por
	# CONTEREM o rotulo positivo como substring (leia-se "des-CONECTADO",
	# "dis-CONNECTED", "dé-CONNECTÉ"). \b garante que so casa no INICIO
	# da palavra "Conectado"/"Connected"/"Connecté" de verdade.
	r"\b" + _label_alt("Conectado", "Connected", r"Connect[eé]", "Verbunden", "Connesso",
		"Подключено", "已连接"), re.I)
RX_IFACE_ROW = re.compile(r"^\s*\d+\s+\d+\s+\d+\s+\S+\s+(.+?)\s*$")

# --- ping ---
RX_PING_AVG = re.compile(_label_alt(r"M[eé]dia", "Media", "Average") + r"\s*=\s*(\d+)\s*ms", re.I)
RX_PING_LOSS = re.compile(_label_alt("Perdidos", "Lost") + r"\s*=\s*(\d+)", re.I)
RX_PING_TTL = re.compile(r"TTL[=:]\s*(\d+)", re.I)
# Linha-resumo do ping ("Pacotes: Enviados = 4, Recebidos = 4, Perdidos = 0
# (0% de perda)," em PT, "Packets: Sent = 4, Received = 4, Lost = 0 (0%
# loss)," em EN, etc.). Em vez de tentar traduzir "Enviados"/"Recebidos"/
# "Perdidos" em 7 idiomas, aproveitamos que a ORDEM e o FORMATO ("=N" tres
# vezes seguido de "(N%") sao sempre os mesmos em qualquer idioma do
# Windows - deteccao estrutural, mais robusta que rotulos traduzidos.
RX_PING_SUMMARY = re.compile(r"=\s*(\d+)[^=\n]*=\s*(\d+)[^=\n]*=\s*(\d+)[^=\n]*\(\s*(\d+)\s*%")
# IP resolvido mostrado entre colchetes na primeira linha do ping (ex.:
# "Disparando google.com [142.250.72.14] com 32 bytes..."). Tambem
# independe de idioma - so aparece quando o destino e um nome, nao um IP.
RX_PING_DEST_IP = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")

# --- tracert ---
# Ultimo grupo usa \S+ (qualquer token sem espaco), nao so [\d\.]+|[\w\.\-]+
# (que aceitava IPv4/hostname mas nao IPv6, por causa do ":") - o Rastreio
# de Rota do menu principal roda so "tracert -d host", sem forcar -4 nem
# -6, entao o Windows escolhe sozinho IPv4 ou IPv6 dependendo de qual o
# DNS resolver primeiro. Se o destino resolver por IPv6 (comum quando a
# rede tem IPv6 funcionando, como confirmado ao vivo no hardware do
# usuario - "google.com" la resolveu para IPv6), a linha inteira vem em
# formato IPv6, e o grupo antigo travava no primeiro ':' do endereco,
# capturando so um pedacinho (ex.: "2" de "2a0c:5a87:..."). \S+ cobre IPv4,
# IPv6, hostname e a primeira palavra de mensagens de timeout localizadas -
# e o motivo de o Rastreio de Rota do menu principal, que roda em IPv4 OU
# IPv6 dependendo do que o usuario escolher (ou do que o Windows resolver
# sozinho, se deixado em automatico), nao precisar de duas expressoes
# separadas.
RX_TRACERT = re.compile(r"^\s*(\d+)\s+((?:(?:<?\d+\s*ms|\*)\s+){1,3})\s*(\S+)")
RX_TRACERT_MS = re.compile(r"<?(\d+)\s*ms")

# --- wi-fi (netsh wlan show interfaces / show profile) ---
RX_SSID = re.compile(r"^\s*SSID\s*:\s*(.+)$", re.I | re.M)
# Rotulo "Name" que abre cada bloco de adaptador em "netsh wlan show
# interfaces" - com mais de um radio Wi-Fi na maquina, o Windows imprime
# um bloco completo por adaptador, cada um comecando com esta linha.
# Confianca alta so em EN/PT/ES (testado); demais idiomas sao melhor
# esforco e podem precisar de ajuste com uma saida real nesse idioma.
RX_WLAN_NAME = re.compile(
	_label_alt("Name", "Nome", "Nombre", "Nom", "Имя", "名称") + r"\s*:\s*(.+)$", re.I | re.M)
RX_SIGNAL = re.compile(
	_label_alt(r"Se[nñ]al", "Signal", "Sinal", "Segnale", "Сигнал", "信号") + r"\s*:\s*(\d+)%", re.I)
RX_AUTH = re.compile(
	_label_alt(r"Autenticaci[oó]n", "Authentication", r"Autentica.{1,5}o",
		"Authentifizierung", "Autenticazione", "Проверка подлинности", "身份验证")
	+ r"\s*:\s*(.+)", re.I)
RX_KEY = re.compile(
	_label_alt(r"Contenido\s+de\s+la\s+clave", "Key\\s+Content",
		r"Conte.{1,3}do\s+da\s+.{1,6}have", r"Contenu\s+de\s+la\s+cl[eé]",
		r"Schl[uü]sselinhalt", "Contenuto\\s+chiave", r"Содержимое\s+ключа", "密钥内容")
	+ r"\s*:\s*(.+)", re.I)
RX_WLAN_BSSID = re.compile(r"BSSID\s*:?\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", re.I)
RX_WLAN_CHANNEL = re.compile(
	_label_alt("Channel", "Canal", "Kanal", "Канал", "信道", "通道") + r"\s*:?\s*(\d+)", re.I)
RX_WLAN_RADIO = re.compile(
	_label_alt(r"Radio\s+type", r"Tipo\s+de\s+r[aá]dio", r"Tipo\s+de\s+radio",
		"Type\\s+radio", "Funktyp", "Tipo\\s+radio", "Тип\\s+радио", "无线电类型")
	+ r"\s*:?\s*(.+)", re.I)
RX_WLAN_RATE = re.compile(
	_label_alt(r"Receive\s+rate\s*\(Mbps\)", r"Velocidad\s+de\s+recepci[oó]n",
		r"Taxa\s+de\s+recep[cç][aã]o", r"D[eé]bit\s+de\s+r[eé]ception", "Empfangsrate",
		r"Velocit[aà]\s+di\s+ricezione", "Скорость\\s+приема", "接收速率")
	# Entre o rotulo e o numero pode vir texto como "(Mbps)" (nos idiomas
	# em que isso nao faz parte do proprio rotulo) - por isso o preenchimento
	# aceita qualquer coisa que NAO seja digito, em vez de um "\S*" que
	# tambem aceitaria digitos por engano. A captura do numero em si fica
	# limitada a UM numero bem formado (inteiro + no maximo uma casa
	# decimal), em vez de "[\d.,]+" solto, que podia grudar digitos de
	# campos vizinhos numa captura so (gerando valores absurdos tipo
	# "2460.4" em vez do valor real reportado pelo Windows).
	+ r"[^\d\n]{0,15}(\d+(?:[.,]\d+)?)", re.I)
# Nomes tipicos de adaptador Wi-Fi (o Windows geralmente usa "Wi-Fi" sem
# traduzir, mas cobrimos variantes/renomeios comuns tambem).
RX_WIFI_IFACE_NAME = re.compile(r"wi-?fi|wlan|wireless|802\.11|无线", re.I)

# --- nslookup (IP publico) ---
RX_NSLOOKUP = re.compile(r"Address(?:es)?\s*[=:]\s*" + IP, re.I)
# IPs dos proprios resolvers anycast do OpenDNS (resolver1/resolver2). Se a
# consulta a myip.opendns.com devolver um destes enderecos, a resposta nao
# veio do servico real de deteccao de IP - o DNS da rede esta interceptando
# ou redirecionando a consulta (comum atras de CGNAT, DNS forcado pelo
# roteador/operadora, ou proxies transparentes), e o que voltou foi o IP do
# proprio servidor que respondeu, nao o IP publico do usuario.
OPENDNS_RESOLVER_IPS = {"208.67.222.222", "208.67.220.220", "208.67.222.220", "208.67.220.222"}

# --- netsh interface ip show config (metodo primario, mais rapido) ---
RX_NETSH_IP = re.compile(
	_label_alt("IP\\s+Address", r"Direcci[oó]n\s+IP", r"Endere[cç]o\s+IP", "Adresse\\s+IP",
		"IP-Adresse", "Indirizzo\\s+IP", "IP[- ]?адрес", "IP\\s*地址")
	+ r"\s*[:\.]?\s*" + IP, re.I)
# A mascara NAO aparece direto apos os dois-pontos: o netsh mostra algo como
# "Subnet Prefix: 192.168.1.0/24 (mask 255.255.255.0)" — o valor real esta
# dentro dos parenteses "(mask X)". Ler o primeiro IP da linha (bug antigo)
# pegava o endereco de rede (192.168.1.0) em vez da mascara real.
RX_NETSH_MASK = re.compile(
	r"\(" + _label_alt("mask", r"m[aá]scara", "masque", "maske", "maschera", "маска", "掩码")
	+ r"\s+" + IP + r"\)", re.I)
RX_NETSH_GW = re.compile(
	_label_alt("Default\\s+Gateway", r"Puerta\s+de\s+enlace(?:\s+predeterminada)?",
		r"Gateway\s+Padr[ãa]o", r"Passerelle(?:\s+par\s+d[eé]faut)?",
		"Standardgateway", "Gateway\\s+predefinito", "Основной\\s+шлюз", "默认网关")
	+ r"\s*[:\.]?\s*" + IP, re.I)
# Aceita texto extra entre o rotulo e os dois-pontos, pois o netsh usa
# frases como "DNS servers configured through DHCP:" ou
# "Statically Configured DNS Servers:", nao so "DNS Servers:".
RX_NETSH_DNS = re.compile(
	_label_alt("DNS\\s+Servers?", r"Servidores\s+DNS", r"Serveurs\s+DNS", "DNS-Server",
		r"Server\s+DNS", "Серверы\\s+DNS", "DNS\\s*服务器")
	+ r".{0,60}?:\s*" + IP, re.I)
# Nome da interface: em vez de depender de tradução do verbo
# ("Configuration for interface" / "Configuración de IP para..."), pega
# qualquer linha de cabecalho (sem indentacao) que contenha um nome entre
# aspas — funciona em qualquer idioma do Windows.
RX_NETSH_IF = re.compile(r'^\S.*?"(.+?)"\s*$', re.M)
# Adaptadores virtuais/tuneis que nao devem ser confundidos com a conexao
# real (VPN, Hyper-V, WSL, loopback etc.)
RX_VIRTUAL_IFACE = re.compile(
	r"virtual|loopback|v[e]?thernet|\bvpn\b|\btap\b|tailscale|zerotier|"
	r"hyper-?v|wsl|bluetooth|tunnel|tunel", re.I)
# Adaptadores "fantasma" do Windows (WAN Miniport de PPTP/L2TP/SSTP/IKEv2,
# entre outros dispositivos ocultos) - o Windows sempre os nomeia com um
# asterisco no final (ex.: "Conexao local* 2", "Local Area Connection* 9"),
# convencao que independe de idioma. Nunca sao uteis para selecionar
# manualmente, entao ficam de fora do seletor de interface.
RX_HIDDEN_IFACE = re.compile(r"\*\s*\d*\s*$")
RX_DHCP = re.compile(
	_label_alt("DHCP\\s+enabled", "DHCP\\s+habilitado", r"DHCP\s+activ[eé]",
		"DHCP\\s+aktiviert", "DHCP\\s+abilitato", "DHCP\\s+включен", "DHCP\\s+已启用")
	+ r"\s*:?\s*(.+)", re.I)
DHCP_YES_WORDS = {"yes", "sí", "si", "sim", "oui", "ja", "sì", "да", "是"}

# --- netsh advfirewall show allprofiles state ---
# O texto "ON"/"OFF" ao lado de "State" tambem costuma vir traduzido pelo
# Windows dependendo da versao. Reaproveita o mesmo espirito de
# DHCP_YES_WORDS: uma lista de palavras conhecidas que significam "ligado"
# em cada idioma suportado, para nao depender so do literal em ingles.
ON_WORDS = {"on", "activado", "activada", "ativado", "activé", "activada",
	"aktiviert", "attivo", "attiva", "включено", "开启", "已启用"}

# --- netsh advfirewall firewall show rule (campo "Action") ---
# Mesmo espirito de DHCP_YES_WORDS/ON_WORDS: o rotulo de acao "Allow" vem
# traduzido conforme o idioma do Windows. Usado por
# firewall.find_matching_active_rule para so considerar regras que de
# fato PERMITEM a porta (nao as que bloqueiam).
ALLOW_WORDS = {"allow", "permitir", "autoriser", "zulassen", "consentito",
	"consenti", "разрешить", "允许"}
