# -*- coding: utf-8 -*-
# Coleta e acoes de firewall/portas (netstat, tasklist, netsh advfirewall).
# Mesma regra de netinfo.py: nada aqui depende de wx/gui/ui do NVDA - cada
# funcao recebe entradas simples e devolve dados (str, dict, list, tupla).
# Quem decide como mostrar/perguntar ao usuario e globalPlugins/networkTools.py.

import re
import csv
import io
import ntpath
import socket

from . import regexes as rx
from .sysutils import run, run_rc

# Prefixo usado por padrao no NOME SUGERIDO de toda regra criada por este
# complemento (o usuario pode trocar o nome livremente no dialogo de
# criacao). Serve para deixar claro, para quem olhar o Firewall do
# Windows depois, que aquela regra veio do Network Tools - a tela de
# Remover Regra usa isto so para ORDENAR a lista (regras proprias
# primeiro), nao mais para filtrar o que aparece nela.
RULE_PREFIX = "NetworkTools - "

# Campos na ORDEM FIXA em que "netsh advfirewall firewall show rule"
# sempre os imprime (Enabled, Direction, Profiles, Grouping, LocalIP,
# RemoteIP, Protocol, LocalPort, RemotePort, Edge traversal, Action). Os
# ROTULOS mudam de idioma conforme o Windows, mas a ORDEM nao muda - entao
# extraimos cada valor pela POSICAO da linha dentro do bloco, nao pelo
# texto do rotulo (mesma tecnica ja usada em get_mac_address para o CSV
# do getmac).
_CAMPOS_REGRA = ["enabled", "direction", "profiles", "grouping", "localip",
	"remoteip", "protocol", "localport", "remoteport", "edge", "action"]


def _valor_apos_dois_pontos(linha):
	idx = linha.find(":")
	return linha[idx + 1:].strip() if idx != -1 else ""


# ---------------------------------------------------------------------------
# 1) Portas realmente escutando agora
# ---------------------------------------------------------------------------

def _mapa_pid_processo():
	"""PID -> nome do processo, via tasklist. Le por POSICAO de coluna do
	CSV (0=nome, 1=PID), nao pelo cabecalho (que nao existe aqui por causa
	de /nh) - entao funciona em qualquer idioma do Windows."""
	ok, out = run(["tasklist", "/fo", "csv", "/nh"], timeout=5)
	mapa = {}
	if not ok or not out.strip():
		return mapa
	try:
		linhas = list(csv.reader(io.StringIO(out)))
	except Exception:
		return mapa
	for linha in linhas:
		if len(linha) >= 2 and linha[1].strip().isdigit():
			mapa[int(linha[1].strip())] = linha[0].strip()
	return mapa


def list_listening_ports():
	"""Lista as portas TCP/UDP que tem algo REALMENTE escutando agora,
	junto com o processo responsavel.

	Em vez de tentar reconhecer a palavra "LISTENING" traduzida (que muda
	de idioma: "ESCUTANDO", "ESCUCHANDO", "ECOUTE", "ABHOREN" etc.), usamos
	um sinal estrutural que NAO muda com o idioma: uma linha TCP com
	endereco remoto "0.0.0.0:0" (ou "[::]:0" em IPv6) so existe para um
	socket em modo de escuta - conexoes de verdade sempre mostram um IP
	remoto real. Para UDP nao ha "estado" nenhum no netstat (protocolo sem
	conexao) - todo socket UDP local listado ja esta "escutando" por
	definicao."""
	ok, out = run(["netstat", "-ano"], timeout=10)
	if not ok or not out.strip():
		return []
	pid_map = _mapa_pid_processo()
	achados = []
	for linha in out.splitlines():
		partes = linha.split()
		if not partes:
			continue
		proto = partes[0].upper()
		if proto == "TCP" and len(partes) == 5:
			local, remoto, _, pid_str = partes[1], partes[2], partes[3], partes[4]
			if remoto not in ("0.0.0.0:0", "[::]:0"):
				continue
		elif proto == "UDP" and len(partes) == 4:
			local, remoto, pid_str = partes[1], partes[2], partes[3]
		else:
			continue
		if not pid_str.isdigit():
			continue
		try:
			_addr, porta = local.rsplit(":", 1)
		except ValueError:
			continue
		if not porta.isdigit():
			continue
		pid = int(pid_str)
		achados.append({
			"protocolo": proto,
			"porta": int(porta),
			"endereco_local": local,
			"pid": pid,
			"processo": pid_map.get(pid, "?"),
		})
	# Remove duplicatas (o mesmo par protocolo/porta/pid pode aparecer
	# 2 vezes, uma para IPv4 e outra para IPv6).
	vistos = set()
	unicos = []
	for item in achados:
		chave = (item["protocolo"], item["porta"], item["pid"])
		if chave in vistos:
			continue
		vistos.add(chave)
		unicos.append(item)
	unicos.sort(key=lambda i: (i["porta"], i["protocolo"]))
	return unicos


# ---------------------------------------------------------------------------
# 2) Regras de firewall ativas / listagem interna para remocao
# ---------------------------------------------------------------------------

def list_firewall_rules(direction="in"):
	"""Le TODAS as regras de firewall na direcao pedida ("in" ou "out"),
	independente de quem as criou (Windows, outro programa, ou este
	complemento)."""
	ok, out = run(
		["netsh", "advfirewall", "firewall", "show", "rule", "name=all", f"dir={direction}"],
		timeout=20,
	)
	if not ok or not out.strip():
		return []
	blocos = re.split(r"\r?\n\s*\r?\n", out.strip())
	regras = []
	for bloco in blocos:
		linhas = [l for l in bloco.splitlines() if l.strip()]
		if not linhas:
			continue
		nome = _valor_apos_dois_pontos(linhas[0])
		if not nome:
			continue
		demais = [l for l in linhas[1:] if not re.match(r"^-{3,}\s*$", l.strip())]
		valores = [_valor_apos_dois_pontos(l) for l in demais]
		d = dict(zip(_CAMPOS_REGRA, valores))
		d["nome"] = nome
		d["ativa"] = d.get("enabled", "").strip().lower() in rx.DHCP_YES_WORDS
		regras.append(d)
	return regras


def list_active_rules(direction="in"):
	"""So as regras (na direcao pedida) que estao de fato ATIVAS agora - e
	o que responde "o que esta permitido entrar/sair desta maquina hoje",
	que e a pergunta real por tras do item de menu "Ver regras de firewall
	ativas". Direction "in" = entrada, "out" = saida."""
	return [r for r in list_firewall_rules(direction) if r.get("ativa")]


def list_removable_rules():
	"""TODAS as regras de firewall, de entrada e de saida, ativas ou nao,
	criadas pelo Windows, por outros programas, OU por este complemento -
	usado pela tela de Remover Regra.

	Antes, esta funcao (list_own_rules) so devolvia regras com nome
	comecando com RULE_PREFIX, para nunca expor as centenas de regras
	padrao do Windows. Isso mudou a pedido do usuario: para um tecnico de
	rede, poder remover QUALQUER regra (nao so as que o complemento
	criou) e o ponto principal desta tela. A seguranca contra remocao
	acidental agora fica por conta da confirmacao extra pedida na camada
	de interface (globalPlugins/networkTools.py) quando a regra escolhida
	NAO comeca com RULE_PREFIX - a lista em si nao filtra mais nada.

	Cada regra devolvida ganha uma chave "direcao" ("in"/"out"), porque o
	mesmo nome de regra pode existir nas duas direcoes ao mesmo tempo (o
	Windows permite) - sem isso nao daria para saber qual das duas
	remover. As regras proprias do complemento aparecem primeiro (mais
	faceis de achar), seguidas do restante em ordem alfabetica."""
	todas = []
	vistos = set()
	for direcao in ("in", "out"):
		for r in list_firewall_rules(direcao):
			nome = r.get("nome", "")
			chave = (nome, direcao)
			if chave in vistos:
				continue
			vistos.add(chave)
			r = dict(r)
			r["direcao"] = direcao
			todas.append(r)
	todas.sort(key=lambda r: (not r["nome"].startswith(RULE_PREFIX), r["nome"].lower(), r["direcao"]))
	return todas


# ---------------------------------------------------------------------------
# 3/4/6) Criar regra de firewall (porta ou programa, entrada ou saida)
# ---------------------------------------------------------------------------

def sugerir_nome_regra(direcao, acao, protocolo=None, porta=None, programa=None):
	"""Monta um nome de regra sugerido (o usuario ve isto pre-preenchido no
	dialogo e pode editar livremente antes de confirmar) a partir do tipo
	de regra e dos valores escolhidos - sempre comecando com RULE_PREFIX,
	a mesma convencao usada desde a primeira versao deste modulo, que
	deixa claro depois, no Firewall do Windows, que a regra veio deste
	complemento."""
	direcao_txt = "Entrada" if direcao == "in" else "Saida"
	acao_txt = "Permitir" if acao == "allow" else "Bloquear"
	if programa:
		# ntpath (nao os.path): o caminho e sempre de Windows, com barra
		# invertida, independente do SO onde este codigo estiver rodando.
		alvo = ntpath.basename(programa.strip('"')) or programa
	else:
		alvo = f"{protocolo} {porta}"
	return f"{RULE_PREFIX}{acao_txt} {direcao_txt} {alvo}"


def add_custom_rule(nome, direcao, acao, protocolo=None, porta=None,
		programa=None, ip_remoto=None, perfis=None, descricao=None):
	"""Cria uma regra de firewall totalmente configuravel. Substitui as
	tres funcoes que existiam antes (add_allow_rule, add_block_rule_port,
	add_block_rule_program) por um unico ponto de montagem do comando
	netsh - as tres faziam basicamente a mesma coisa com pequenas
	variacoes (direcao fixa, acao fixa, porta OU programa), o que so
	duplicava a mesma logica tres vezes.

	Parametros:
	  nome: nome da regra (deve ser unico o bastante para depois remove-la
	        sem afetar outras - ver delete_rule)
	  direcao: "in" ou "out"
	  acao: "allow" ou "block"
	  protocolo + porta: para regra baseada em PORTA (ex.: "TCP", "8080")
	  programa: caminho completo do executavel, para regra baseada em
	        PROGRAMA - informe protocolo/porta OU programa, nao os dois
	  ip_remoto: escopo opcional de origem/destino, no formato aceito
	        pelo proprio netsh (IP unico, CIDR, intervalo, ou lista
	        separada por virgula) - ex.: "192.168.1.10" ou "10.0.0.0/24"
	  perfis: lista com qualquer combinacao de "domain"/"private"/"public";
	        None ou lista vazia = todos os perfis
	  descricao: texto livre opcional, guardado na propria regra do
	        Windows (visivel depois em "netsh advfirewall firewall show
	        rule" ou no Firewall do Windows com Seguranca Avancada)

	Devolve (returncode, saida_do_comando, nome_da_regra_criada)."""
	args = ["netsh", "advfirewall", "firewall", "add", "rule",
		f"name={nome}", f"dir={direcao}", f"action={acao}"]
	if programa:
		args.append(f"program={programa}")
	else:
		args += [f"protocol={protocolo}", f"localport={porta}"]
	if ip_remoto:
		args.append(f"remoteip={ip_remoto}")
	if perfis:
		args.append(f"profile={','.join(perfis)}")
	if descricao:
		args.append(f"description={descricao}")
	rc, out = run_rc(args, timeout=15)
	return rc, out, nome


# ---------------------------------------------------------------------------
# 5) Remover regra existente
# ---------------------------------------------------------------------------

def delete_rule(nome, direcao=None):
	"""Remove a(s) regra(s) com o nome dado. Se `direcao` for informada
	("in"/"out"), so remove a regra daquela direcao especifica - importante
	porque, desde que a remocao passou a listar TODAS as regras (e nao so
	as do complemento), o mesmo nome pode existir nas duas direcoes ao
	mesmo tempo, e remover sem especificar direcao apagaria as duas."""
	args = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={nome}"]
	if direcao:
		args.append(f"dir={direcao}")
	return run_rc(args, timeout=15)


# ---------------------------------------------------------------------------
# 7) Status do firewall por perfil
# ---------------------------------------------------------------------------

def firewall_profiles_state():
	"""Le o estado (ligado/desligado) de cada perfil de rede (Dominio,
	Privado, Publico). O rotulo "State" nao vem seguido de dois-pontos
	neste comando especifico do netsh (formato "State    ON", com espacos,
	nao "State: ON") - entao pegamos sempre a PRIMEIRA linha de conteudo
	de cada bloco (logo apos o titulo e o tracejado) e usamos a ULTIMA
	palavra dela como o valor, o que funciona tanto para "State    ON"
	quanto para variantes traduzidas do rotulo."""
	ok, out = run(["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=15)
	if not ok or not out.strip():
		return []
	blocos = re.split(r"\r?\n\s*\r?\n", out.strip())
	perfis = []
	for bloco in blocos:
		linhas = [l for l in bloco.splitlines() if l.strip()]
		if len(linhas) < 2:
			continue
		titulo = linhas[0].strip().rstrip(":")
		demais = [l for l in linhas[1:] if not re.match(r"^-{3,}\s*$", l.strip())]
		if not demais:
			continue
		partes = demais[0].strip().split()
		if not partes:
			continue
		valor_bruto = partes[-1]
		ligado = valor_bruto.strip().lower() in rx.ON_WORDS
		perfis.append({"perfil": titulo, "valor_bruto": valor_bruto, "ligado": ligado})
	return perfis


# ---------------------------------------------------------------------------
# 8) Testar a porta localmente (sem depender de nenhum servico externo)
# ---------------------------------------------------------------------------
#
# Uma versao anterior deste modulo testava a porta "de fora para dentro"
# atraves do site publico canyouseeme.org. Essa abordagem foi retirada de
# proposito: depender de um site de terceiros, sem contrato de API formal
# por tras, e sem controle nenhum sobre bloqueio de IP por excesso de
# requisicoes, e um risco de suporte inaceitavel para um complemento que
# precisa ser estavel (um usuario que rodasse o teste algumas vezes
# poderia passar a receber erro para TODOS os usuarios atras do mesmo IP
# publico, sem que houvesse nada de errado com a rede dele). O teste
# local abaixo cobre o que a maioria dos usuarios realmente precisa
# (confirmar que algo esta escutando e que o firewall do Windows permite
# a porta) sem sair da maquina.

# Portas que a grande maioria dos provedores de internet residenciais
# bloqueia por padrao, no mundo todo, independente de qualquer
# configuracao de firewall ou de roteador do cliente - historicamente
# associadas a compartilhamento de arquivos do Windows (135/137/138/139/445)
# e a envio de e-mail (25), usadas por vírus/worms no passado. Isto e uma
# lista fixa conhecida (nao uma consulta a internet), entao pode ser usada
# como aviso mesmo dentro de um teste 100% local.
PORTAS_COMUMENTE_BLOQUEADAS_PELO_PROVEDOR = {25, 135, 137, 138, 139, 445}


def _porta_bate_localport(especificacao, porta):
	"""Confere se `porta` esta coberta pelo campo "LocalPort" de uma regra
	de firewall, que pode vir como um numero unico ("80"), uma lista
	("80,443,8080"), um intervalo ("1000-2000"), uma combinacao dos dois,
	ou a palavra "Any"/"Qualquer"/"Todas" (traduzida conforme o idioma do
	Windows - assim como "State ON" em firewall_profiles_state, nao ha
	lista fechada e confiavel de todas as traducoes possiveis). Em vez de
	tentar reconhecer cada traducao de "Any", usamos um sinal estrutural:
	se o campo NAO e composto so por digitos/virgulas/hifens/espacos, ele
	nao pode ser uma lista de portas numerica - logo so pode ser uma
	palavra como "Any", que sempre significa "todas as portas"."""
	texto = (especificacao or "").strip()
	if not texto:
		return False
	if not re.fullmatch(r"[\d,\-\s]+", texto):
		return True
	for parte in texto.split(","):
		parte = parte.strip()
		if not parte:
			continue
		if "-" in parte:
			ini, fim = (p.strip() for p in parte.split("-", 1))
			if ini.isdigit() and fim.isdigit() and int(ini) <= porta <= int(fim):
				return True
		elif parte.isdigit() and int(parte) == porta:
			return True
	return False


def find_matching_active_rule(protocolo, porta, direction="in"):
	"""Procura, entre as regras ATIVAS na direcao pedida, uma que permita
	(acao "Allow"/"Permitir"/etc.) a porta/protocolo informados.

	Distingue dois tipos de regra, porque para o usuario eles significam
	coisas bem diferentes:
	  - regra ESPECIFICA: o campo LocalPort lista um numero/intervalo que
	    inclui a porta pedida (ex.: "54321" ou "50000-60000") - foi feita
	    (por este complemento ou por outro programa) pensando nesta porta.
	  - regra GENERICA: o campo LocalPort e "Any" (ou uma traducao dele) -
	    normalmente criada automaticamente pelo Windows quando um programa
	    (ex.: "Python", um IDE, um jogo) pede permissao de rede pela
	    primeira vez. Ela permite ENTRADA EM QUALQUER PORTA para aquele
	    programa - inclusive a porta pedida, mas nao porque alguem
	    configurou aquela porta especificamente. Encontrar so uma regra
	    dessas nao deve ser lido como "esta porta foi liberada de
	    proposito".

	Uma regra especifica, quando existe, e sempre o resultado mais
	informativo - por isso tem prioridade: so devolvemos uma regra
	generica se nenhuma regra especifica for encontrada.

	Devolve uma tupla (regra_ou_None, especifica_bool). "especifica" so
	tem sentido quando ha uma regra encontrada; e False tanto para "regra
	generica encontrada" quanto para "nenhuma regra encontrada"."""
	protocolo = (protocolo or "").strip().upper()
	porta = int(porta)
	generica = None
	for r in list_firewall_rules(direction):
		if not r.get("ativa"):
			continue
		r_proto = (r.get("protocol") or "").strip().upper()
		# So descarta em caso de incompatibilidade CLARA entre TCP e UDP;
		# qualquer outro valor (ex.: "Any", ou uma traducao dele) e tratado
		# como "cobre todos os protocolos", pelo mesmo motivo estrutural
		# usado em _porta_bate_localport.
		if r_proto in ("TCP", "UDP") and r_proto != protocolo:
			continue
		campo_porta = (r.get("localport") or "").strip()
		if not _porta_bate_localport(campo_porta, porta):
			continue
		acao = (r.get("action") or "").strip().lower()
		if acao not in rx.ALLOW_WORDS:
			continue
		eh_especifica = bool(re.fullmatch(r"[\d,\-\s]+", campo_porta))
		if eh_especifica:
			return r, True
		if generica is None:
			generica = r
	if generica is not None:
		return generica, False
	return None, False


def test_port_local(protocolo, porta, timeout=2):
	"""Testa uma porta usando SOMENTE informacoes e conexoes locais - nunca
	sai da maquina para a internet, entao nao pode falhar por bloqueio de
	IP, instabilidade de um site de terceiros, ou exigir que exista
	conexao com a internet (funciona ate numa rede isolada).

	Junta tres sinais, cada um obtido de uma forma diferente:
	  1) Se ha algum processo REALMENTE escutando na porta agora
	     (reaproveita a mesma logica de list_listening_ports).
	  2) Se existe uma regra de firewall de ENTRADA ativa que permite
	     aquela porta/protocolo (find_matching_active_rule).
	  3) Para TCP, uma tentativa real de conexao a 127.0.0.1:porta - o
	     jeito mais direto de confirmar que algo aceita conexao ali agora.
	     Isto NAO confirma alcance vindo de fora da rede (isso dependeria
	     do NAT do roteador e do provedor, fora do alcance de qualquer
	     teste puramente local) - por isso o resultado e chamado de
	     "conexao local", nunca de "acessivel de fora". Para UDP nao ha
	     "conexao" (protocolo sem estado), entao este item fica None.

	Devolve um dicionario com:
	  "escutando": True/False
	  "processo": nome do processo responsavel (ou None)
	  "pid": PID do processo (ou None)
	  "regra_permite": True/False - existe regra de entrada ativa
	             permitindo esta porta/protocolo
	  "regra_nome": nome da regra encontrada (ou None)
	  "regra_especifica": True se a regra encontrada foi feita para esta
	             porta especificamente; False se foi uma regra generica
	             de programa ("Any"/qualquer porta) que por acaso tambem
	             cobre esta porta; None se nenhuma regra foi encontrada
	  "conexao_local_ok": True/False para TCP; None para UDP (nao testavel)
	  "porta_comumente_bloqueada_pelo_provedor": True se a porta esta
	             entre as que provedores costumam bloquear por padrao -
	             vale avisar o usuario disso, ja que mesmo um resultado
	             local 100% positivo nao garante alcance de fora da rede.
	"""
	protocolo = (protocolo or "").strip().upper()
	porta_int = int(porta)

	escutando, processo, pid = False, None, None
	for item in list_listening_ports():
		if item["porta"] == porta_int and item["protocolo"] == protocolo:
			escutando, processo, pid = True, item["processo"], item["pid"]
			break

	regra, regra_especifica = find_matching_active_rule(protocolo, porta_int, "in")

	conexao_local_ok = None
	if protocolo == "TCP":
		conexao_local_ok = False
		try:
			with socket.create_connection(("127.0.0.1", porta_int), timeout=timeout):
				conexao_local_ok = True
		except Exception:
			conexao_local_ok = False

	return {
		"escutando": escutando,
		"processo": processo,
		"pid": pid,
		"regra_permite": regra is not None,
		"regra_nome": regra.get("nome") if regra else None,
		"regra_especifica": regra_especifica if regra else None,
		"conexao_local_ok": conexao_local_ok,
		"porta_comumente_bloqueada_pelo_provedor": porta_int in PORTAS_COMUMENTE_BLOQUEADAS_PELO_PROVEDOR,
	}
