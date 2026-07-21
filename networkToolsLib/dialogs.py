# -*- coding: utf-8 -*-
# Componentes de interface (dialogos wx). Nao fazem nenhuma coleta ou
# interpretacao de dados de rede - so recebem/mostram texto. A logica de
# "o que perguntar" e "o que fazer com a resposta" fica em
# globalPlugins/networkTools.py; a logica de "como obter os dados" fica
# em networkToolsLib/netinfo.py.

import wx

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
	# Cobre teste isolado deste modulo fora da NVDA (addonHandler nao
	# existe, ou nao acha o addon a partir daqui) - "_" fica so como
	# identidade, suficiente pra nao quebrar o import.
	def _(texto):
		return texto


class AskDialog(wx.Dialog):
	"""Dialogo generico de entrada de texto (usado por Ping, Traceroute,
	Whois etc.)."""

	def __init__(self, parent, title, label, default=""):
		super().__init__(parent, title=title)
		self.value = ""
		s = wx.BoxSizer(wx.VERTICAL)
		s.Add(wx.StaticText(self, label=label), flag=wx.ALL, border=8)
		self._c = wx.TextCtrl(self, value=default)
		s.Add(self._c, flag=wx.EXPAND | wx.ALL, border=8)
		# translators: botao para confirmar um valor digitado
		ok = wx.Button(self, wx.ID_OK, _("&Confirmar"))
		ok.SetDefault()
		# translators: botao para cancelar um dialogo
		ca = wx.Button(self, wx.ID_CANCEL, _("Cancelar"))
		bs = wx.StdDialogButtonSizer()
		bs.AddButton(ok)
		bs.AddButton(ca)
		bs.Realize()
		s.Add(bs, flag=wx.ALIGN_CENTER | wx.BOTTOM, border=8)
		self.SetSizer(s)
		s.Fit(self)
		ok.Bind(wx.EVT_BUTTON, self._ok)
		ca.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_CANCEL))
		self.Bind(wx.EVT_CHAR_HOOK, self._key)
		self.Bind(wx.EVT_SHOW, lambda e: self._c.SetFocus() if e.IsShown() else None)

	def _key(self, e):
		if e.GetKeyCode() == wx.WXK_ESCAPE:
			self.EndModal(wx.ID_CANCEL)
		else:
			e.Skip()

	def _ok(self, e):
		self.value = self._c.GetValue().strip()
		self.EndModal(wx.ID_OK)


class EditableListDialog(wx.Dialog):
	"""Dialogo de texto multi-linha EDITAVEL, para o usuario gerenciar uma
	lista livre (um item por linha) - usado hoje pelos Servidores DNS
	Personalizados, mas escrito de forma generica (so texto/instrucao/
	conteudo inicial) pra poder servir outras listas parecidas no futuro
	sem duplicar o dialogo. Diferente do ResultDialog (so leitura), este
	tem botoes Salvar/Cancelar em vez de so Fechar."""

	def __init__(self, parent, title, instrucao, conteudo_inicial):
		super().__init__(parent, title=title,
			style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
		self.value = None
		s = wx.BoxSizer(wx.VERTICAL)
		s.Add(wx.StaticText(self, label=instrucao), flag=wx.LEFT | wx.TOP | wx.RIGHT, border=8)
		self._t = wx.TextCtrl(self, value=conteudo_inicial, style=wx.TE_MULTILINE | wx.TE_RICH2)
		self._t.SetMinSize((480, 260))
		s.Add(self._t, 1, wx.EXPAND | wx.ALL, 8)
		# translators: botao para salvar as alteracoes feitas na lista editavel
		ok = wx.Button(self, wx.ID_OK, _("&Salvar"))
		ok.SetDefault()
		ca = wx.Button(self, wx.ID_CANCEL, _("Cancelar"))
		bs = wx.StdDialogButtonSizer()
		bs.AddButton(ok)
		bs.AddButton(ca)
		bs.Realize()
		s.Add(bs, flag=wx.ALIGN_CENTER | wx.BOTTOM, border=8)
		self.SetSizer(s)
		s.Fit(self)
		ok.Bind(wx.EVT_BUTTON, self._ok)
		ca.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_CANCEL))
		self.Bind(wx.EVT_CHAR_HOOK, self._key)
		self.Bind(wx.EVT_SHOW, lambda e: self._t.SetFocus() if e.IsShown() else None)

	def _key(self, e):
		# Escape cancela o dialogo, MAS so quando o foco nao esta dentro
		# da propria caixa de texto multilinha - dentro dela, Escape e
		# uma tecla comum de edicao/navegacao (e o Ctrl+Tab entre abas
		# tambem nao existe aqui, entao nao ha ambiguidade de foco a
		# resolver como no MenuDialog).
		if e.GetKeyCode() == wx.WXK_ESCAPE:
			self.EndModal(wx.ID_CANCEL)
		else:
			e.Skip()

	def _ok(self, e):
		self.value = self._t.GetValue()
		self.EndModal(wx.ID_OK)


class ResultDialog(wx.Dialog):
	"""Dialogo generico de exibicao de resultado (texto multilinha
	somente leitura)."""

	def __init__(self, parent, title, content):
		super().__init__(parent, title=title,
			style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
		s = wx.BoxSizer(wx.VERTICAL)
		t = wx.TextCtrl(self, value=content,
			style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2)
		t.SetMinSize((480, 260))
		# translators: botao para fechar a janela de resultado e voltar ao menu
		btn = wx.Button(self, wx.ID_CLOSE, _("&Fechar"))
		btn.SetDefault()
		btn.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_CLOSE))
		s.Add(t, 1, wx.EXPAND | wx.ALL, 8)
		s.Add(btn, flag=wx.ALIGN_CENTER | wx.BOTTOM, border=8)
		self.SetSizer(s)
		s.Fit(self)
		self.Bind(wx.EVT_CHAR_HOOK, self._key)
		self.Bind(wx.EVT_SHOW, lambda e: t.SetFocus() if e.IsShown() else None)

	def _key(self, e):
		if e.GetKeyCode() == wx.WXK_ESCAPE:
			self.EndModal(wx.ID_CLOSE)
		else:
			e.Skip()


class TabbedResultDialog(wx.Dialog):
	"""Dialogo de exibicao de resultado dividido em ABAS reais (wx.Notebook)
	- uma caixa de texto somente leitura por aba, cada uma com seu proprio
	conteudo.

	Criado especificamente para resolver um problema de acessibilidade
	relatado com ResultDialog: quando o resultado tinha secoes bem
	distintas (ex.: regras de Entrada e de Saida), tudo ficava concatenado
	num unico texto longo, e um usuario de leitor de tela precisava
	navegar linha por linha ate achar onde a secao seguinte comecava. Com
	abas de verdade, o NVDA anuncia "aba, X de Y" e Ctrl+Tab/Ctrl+Shift+Tab
	pulam direto de uma secao para a outra, sem precisar varrer texto."""

	def __init__(self, parent, title, tabs):
		"""tabs: lista de tuplas (rotulo_da_aba, conteudo_da_aba)."""
		super().__init__(parent, title=title,
			style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
		s = wx.BoxSizer(wx.VERTICAL)
		nb = wx.Notebook(self)
		self._first_text = None
		for rotulo, conteudo in tabs:
			painel = wx.Panel(nb)
			ps = wx.BoxSizer(wx.VERTICAL)
			t = wx.TextCtrl(painel, value=conteudo,
				style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2)
			t.SetMinSize((480, 260))
			ps.Add(t, 1, wx.EXPAND | wx.ALL, 8)
			painel.SetSizer(ps)
			nb.AddPage(painel, rotulo)
			if self._first_text is None:
				self._first_text = t
		# translators: botao para fechar a janela de resultado e voltar ao menu
		btn = wx.Button(self, wx.ID_CLOSE, _("&Fechar"))
		btn.SetDefault()
		btn.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_CLOSE))
		s.Add(nb, 1, wx.EXPAND | wx.ALL, 8)
		s.Add(btn, flag=wx.ALIGN_CENTER | wx.BOTTOM, border=8)
		self.SetSizer(s)
		s.Fit(self)
		self.Bind(wx.EVT_CHAR_HOOK, self._key)
		self.Bind(wx.EVT_SHOW,
			lambda e: self._first_text.SetFocus() if e.IsShown() and self._first_text else None)

	def _key(self, e):
		if e.GetKeyCode() == wx.WXK_ESCAPE:
			self.EndModal(wx.ID_CLOSE)
		else:
			e.Skip()


class DnsBestDialog(wx.Dialog):
	"""Dialogo de resultado da busca de "Melhor DNS".

	Criado para resolver o mesmo tipo de problema de acessibilidade que
	motivou o TabbedResultDialog: um wx.MessageDialog com o ranking inteiro
	como um unico bloco de texto obrigava o usuario a ouvir tudo de uma vez,
	sem conseguir pular de servidor em servidor. Aqui o ranking vira uma
	LISTA de verdade (wx.ListBox, uma linha por servidor) - Seta Cima/Baixo
	navega item a item, igual ao ListBox de acoes do menu principal. Os
	botoes Sim/Nao ficam ao final, numa ordem de navegacao previsivel
	(Tab a partir da lista chega neles direto).

	ranking: lista de strings, uma por servidor testado (ja formatada por
	quem chama - rotulo, endereco, latencia). atual_txt/pergunta: frases
	fixas mostradas abaixo da lista, antes dos botoes."""

	def __init__(self, parent, title, ranking, atual_txt, pergunta):
		super().__init__(parent, title=title,
			style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
		s = wx.BoxSizer(wx.VERTICAL)
		# translators: rotulo acima da lista com o ranking dos servidores DNS testados
		s.Add(wx.StaticText(self, label=_("Ranking dos servidores testados (mais rápido primeiro):")),
			flag=wx.LEFT | wx.RIGHT | wx.TOP, border=8)
		self._lb = wx.ListBox(self, style=wx.LB_SINGLE)
		for item in ranking:
			self._lb.Append(item)
		if ranking:
			self._lb.SetSelection(0)
		self._lb.SetMinSize((480, 220))
		s.Add(self._lb, 1, wx.EXPAND | wx.ALL, border=8)
		s.Add(wx.StaticText(self, label=atual_txt),
			flag=wx.LEFT | wx.RIGHT | wx.TOP, border=8)
		s.Add(wx.StaticText(self, label=pergunta),
			flag=wx.LEFT | wx.RIGHT | wx.TOP | wx.BOTTOM, border=8)
		btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
		# translators: botao para confirmar a troca para o DNS mais rapido encontrado
		self._sim = wx.Button(self, wx.ID_YES, _("&Sim, trocar"))
		self._sim.SetDefault()
		# translators: botao para manter o DNS atual, sem trocar nada
		nao = wx.Button(self, wx.ID_NO, _("&Não, manter atual"))
		btn_sizer.Add(self._sim, flag=wx.RIGHT, border=8)
		btn_sizer.Add(nao)
		s.Add(btn_sizer, flag=wx.ALIGN_CENTER | wx.BOTTOM, border=8)
		self.SetSizer(s)
		s.Fit(self)
		self._sim.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_YES))
		nao.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_NO))
		self.Bind(wx.EVT_CHAR_HOOK, self._key)
		# Foco inicial na lista - assim quem abre o dialogo ja cai revisando
		# o ranking, e chega nos botoes com Tab quando estiver pronto pra
		# decidir (mesmo padrao de foco inicial do MenuDialog).
		self.Bind(wx.EVT_SHOW, lambda e: self._lb.SetFocus() if e.IsShown() else None)

	def _key(self, e):
		# Escape decide "Nao" (mantem o DNS atual) em vez de so fechar sem
		# resposta - aqui, ao contrario dos dialogos so-informativos, o
		# cancelamento tem um significado claro (nao trocar).
		if e.GetKeyCode() == wx.WXK_ESCAPE:
			self.EndModal(wx.ID_NO)
		else:
			e.Skip()


class StaticIPDialog(wx.Dialog):
	"""Dialogo de configuracao manual de IP estatico (IP/mascara/gateway).
	Os campos vem PRE-PREENCHIDOS com a configuracao ATUAL da interface
	(ip_atual/mask_atual/gw_atual, lidos por quem chama antes de abrir o
	dialogo) quando disponivel - MUITO mais util do que um exemplo fixo
	tipo "192.168.1.100" sem nenhuma relacao com a rede de verdade do
	usuario (que parecia "aleatorio" por nao bater com a rede real,
	confirmado ao vivo). Editar 1-2 campos (ex.: so trocar o ultimo
	numero do IP, mantendo mascara/gateway) fica bem mais rapido do que
	digitar tudo do zero. Quando a interface nao tiver nenhum IP
	configurado ainda, os campos vem em branco."""

	def __init__(self, parent, ip_atual="", mask_atual="", gw_atual=""):
		# translators: titulo do dialogo de configuracao de IP estatico
		super().__init__(parent, title=_("Configurar IP Estático"))
		self.ip = self.mask = self.gateway = ""
		s = wx.BoxSizer(wx.VERTICAL)
		def _f(lbl, val):
			s.Add(wx.StaticText(self, label=lbl), flag=wx.LEFT|wx.TOP, border=8)
			c = wx.TextCtrl(self, value=val)
			s.Add(c, flag=wx.EXPAND|wx.LEFT|wx.RIGHT, border=8)
			return c
		# translators: rotulo do campo de endereco IPv4
		self._ip  = _f(_("Endereço IPv4:"),      ip_atual)
		# translators: rotulo do campo de mascara de sub-rede
		self._msk = _f(_("Máscara Sub-rede:"),   mask_atual)
		# translators: rotulo do campo de gateway padrao
		self._gw  = _f(_("Gateway Padrão:"),     gw_atual)
		# translators: botao para aplicar a configuracao de IP estatico
		ok = wx.Button(self, wx.ID_OK, _("&Aplicar"))
		ok.SetDefault()
		ca = wx.Button(self, wx.ID_CANCEL, _("Cancelar"))
		bs = wx.StdDialogButtonSizer()
		bs.AddButton(ok)
		bs.AddButton(ca)
		bs.Realize()
		s.Add(bs, flag=wx.ALIGN_CENTER|wx.ALL, border=8)
		self.SetSizer(s)
		s.Fit(self)
		ok.Bind(wx.EVT_BUTTON, self._ok)
		ca.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_CANCEL))
		self.Bind(wx.EVT_SHOW, lambda e: self._ip.SetFocus() if e.IsShown() else None)

	def _ok(self, e):
		self.ip = self._ip.GetValue().strip()
		self.mask = self._msk.GetValue().strip()
		self.gateway = self._gw.GetValue().strip()
		self.EndModal(wx.ID_OK)


class CustomDNSDialog(wx.Dialog):
	"""Dialogo de aplicar DNS personalizado, com DOIS campos (primario e
	secundario) - nao so um.

	Isto existe por causa de um comportamento do proprio netsh que nao e
	obvio: "netsh interface ip set dns ... addr=X" SUBSTITUI toda a lista
	de servidores DNS da interface por um unico endereco, apagando
	silenciosamente qualquer servidor secundario que ja estivesse
	configurado. Por isso este dialogo pede o secundario explicitamente -
	se o usuario quiser manter um que ja tinha, digita-o aqui; deixando em
	branco, nenhum secundario e configurado (e o que ja existia continua
	sendo substituido, como sempre foi o comportamento do netsh)."""

	def __init__(self, parent, title, secundario_atual=""):
		super().__init__(parent, title=title)
		self.primario = ""
		self.secundario = ""
		s = wx.BoxSizer(wx.VERTICAL)
		def _f(lbl, val):
			s.Add(wx.StaticText(self, label=lbl), flag=wx.LEFT | wx.TOP, border=8)
			c = wx.TextCtrl(self, value=val)
			s.Add(c, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)
			return c
		# translators: rotulo do campo de DNS primario
		self._pri = _f(_("DNS primário:"), "")
		# translators: rotulo do campo de DNS secundario, opcional
		self._sec = _f(_("DNS secundário (opcional):"), secundario_atual)
		ok = wx.Button(self, wx.ID_OK, _("&Confirmar"))
		ok.SetDefault()
		ca = wx.Button(self, wx.ID_CANCEL, _("Cancelar"))
		bs = wx.StdDialogButtonSizer()
		bs.AddButton(ok)
		bs.AddButton(ca)
		bs.Realize()
		s.Add(bs, flag=wx.ALIGN_CENTER | wx.ALL, border=8)
		self.SetSizer(s)
		s.Fit(self)
		ok.Bind(wx.EVT_BUTTON, self._ok)
		ca.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_CANCEL))
		self.Bind(wx.EVT_SHOW, lambda e: self._pri.SetFocus() if e.IsShown() else None)

	def _ok(self, e):
		self.primario = self._pri.GetValue().strip()
		self.secundario = self._sec.GetValue().strip()
		self.EndModal(wx.ID_OK)


class FirewallPortDialog(wx.Dialog):
	"""Dialogo de porta + protocolo, reutilizado tanto para "Abrir porta
	nova" quanto para "Fechar porta" (o titulo passado por quem chama e
	que diferencia as duas telas para o usuario)."""

	def __init__(self, parent, title):
		super().__init__(parent, title=title)
		self.porta = ""
		self.protocolo = "TCP"
		s = wx.BoxSizer(wx.VERTICAL)
		# translators: rotulo do campo de numero da porta
		s.Add(wx.StaticText(self, label=_("Número da porta (1 a 65535):")),
			flag=wx.LEFT | wx.TOP, border=8)
		self._porta = wx.TextCtrl(self)
		s.Add(self._porta, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)
		# translators: rotulo do grupo de opcoes de protocolo (TCP/UDP)
		self._proto = wx.RadioBox(self, label=_("Protocolo"),
			choices=["TCP", "UDP"], majorDimension=1)
		s.Add(self._proto, flag=wx.EXPAND | wx.ALL, border=8)
		ok = wx.Button(self, wx.ID_OK, _("&Confirmar"))
		ok.SetDefault()
		ca = wx.Button(self, wx.ID_CANCEL, _("Cancelar"))
		bs = wx.StdDialogButtonSizer()
		bs.AddButton(ok)
		bs.AddButton(ca)
		bs.Realize()
		s.Add(bs, flag=wx.ALIGN_CENTER | wx.BOTTOM, border=8)
		self.SetSizer(s)
		s.Fit(self)
		ok.Bind(wx.EVT_BUTTON, self._ok)
		ca.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_CANCEL))
		self.Bind(wx.EVT_CHAR_HOOK, self._key)
		self.Bind(wx.EVT_SHOW, lambda e: self._porta.SetFocus() if e.IsShown() else None)

	def _key(self, e):
		if e.GetKeyCode() == wx.WXK_ESCAPE:
			self.EndModal(wx.ID_CANCEL)
		else:
			e.Skip()

	def _ok(self, e):
		self.porta = self._porta.GetValue().strip()
		self.protocolo = self._proto.GetStringSelection() or "TCP"
		self.EndModal(wx.ID_OK)


class FirewallRuleDialog(wx.Dialog):
	"""Dialogo completo de criacao de regra de firewall - cobre os mesmos
	campos que o assistente de "Nova Regra" do proprio Firewall do
	Windows: tipo (porta ou programa), direcao, porta/protocolo OU
	programa, IP remoto (escopo), acao, perfis de rede, nome e descricao.

	So RECOLHE os valores digitados/selecionados - nao valida nada (ex.:
	se a porta e um numero valido) e nao sabe nada sobre as palavras-chave
	que o netsh espera. Por isso os campos de escolha unica (tipo,
	direcao, acao) expoem o INDICE selecionado (0 ou 1) em vez do texto
	traduzido do RadioBox - assim o significado de cada opcao nao muda
	conforme o idioma da interface (quem le o indice e quem decide o que
	ele significa e globalPlugins/networkTools.py, a mesma divisao de
	responsabilidade do resto deste arquivo)."""

	def __init__(self, parent, title, nome_sugerido=""):
		super().__init__(parent, title=title,
			style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
		self.tipo = 0
		self.direcao = 0
		self.porta = ""
		self.protocolo = "TCP"
		self.programa = ""
		self.ip_remoto = ""
		self.acao = 0
		self.perfil_dominio = True
		self.perfil_privado = True
		self.perfil_publico = True
		self.nome = ""
		self.descricao = ""

		s = wx.BoxSizer(wx.VERTICAL)

		# translators: rotulo do grupo de escolha entre regra por porta ou por programa
		self._tipo = wx.RadioBox(self, label=_("Tipo de regra"),
			choices=[_("Baseada em Porta"), _("Baseada em Programa")], majorDimension=1)
		s.Add(self._tipo, flag=wx.EXPAND | wx.ALL, border=8)

		# translators: rotulo do grupo de escolha de direcao da regra
		self._direcao = wx.RadioBox(self, label=_("Direção"),
			choices=[_("Entrada (tráfego chegando)"), _("Saída (tráfego saindo)")], majorDimension=1)
		s.Add(self._direcao, flag=wx.EXPAND | wx.ALL, border=8)

		# translators: rotulo do campo de porta, preenchido so se o tipo de regra for "baseada em porta"
		s.Add(wx.StaticText(self, label=_("Porta (se a regra for baseada em porta):")),
			flag=wx.LEFT | wx.TOP, border=8)
		self._porta = wx.TextCtrl(self)
		s.Add(self._porta, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)
		# translators: rotulo do grupo de protocolo, usado junto com a porta
		self._proto = wx.RadioBox(self, label=_("Protocolo"),
			choices=["TCP", "UDP"], majorDimension=1)
		s.Add(self._proto, flag=wx.EXPAND | wx.ALL, border=8)

		# translators: rotulo do campo de caminho do executavel, preenchido so se o tipo de regra for "baseada em programa"
		s.Add(wx.StaticText(self,
			label=_("Caminho completo do programa (se a regra for baseada em programa):")),
			flag=wx.LEFT | wx.TOP, border=8)
		self._programa = wx.TextCtrl(self)
		s.Add(self._programa, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)

		# translators: rotulo do campo de endereco IP remoto - campo opcional, mas recomendado
		s.Add(wx.StaticText(self,
			label=_("Endereços IP remotos (opcional, ex.: 192.168.1.10 ou 10.0.0.0/24):")),
			flag=wx.LEFT | wx.TOP, border=8)
		self._ip = wx.TextCtrl(self)
		s.Add(self._ip, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)

		# translators: rotulo do grupo de escolha entre permitir ou bloquear
		self._acao = wx.RadioBox(self, label=_("Ação"),
			choices=[_("Permitir"), _("Bloquear")], majorDimension=1)
		s.Add(self._acao, flag=wx.EXPAND | wx.ALL, border=8)

		# translators: titulo do grupo de caixas de selecao dos perfis de rede
		perfis_box = wx.StaticBox(self, label=_("Perfis de Rede"))
		perfis_sizer = wx.StaticBoxSizer(perfis_box, wx.VERTICAL)
		# translators: caixa de selecao do perfil de rede de dominio
		self._perfil_dominio = wx.CheckBox(self, label=_("Domínio"))
		self._perfil_dominio.SetValue(True)
		# translators: caixa de selecao do perfil de rede privado
		self._perfil_privado = wx.CheckBox(self, label=_("Privado"))
		self._perfil_privado.SetValue(True)
		# translators: caixa de selecao do perfil de rede publico
		self._perfil_publico = wx.CheckBox(self, label=_("Público"))
		self._perfil_publico.SetValue(True)
		perfis_sizer.Add(self._perfil_dominio, flag=wx.ALL, border=4)
		perfis_sizer.Add(self._perfil_privado, flag=wx.ALL, border=4)
		perfis_sizer.Add(self._perfil_publico, flag=wx.ALL, border=4)
		s.Add(perfis_sizer, flag=wx.EXPAND | wx.ALL, border=8)

		# translators: rotulo do campo de nome da regra
		s.Add(wx.StaticText(self, label=_("Nome da regra:")),
			flag=wx.LEFT | wx.TOP, border=8)
		self._nome = wx.TextCtrl(self, value=nome_sugerido)
		s.Add(self._nome, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)

		# translators: rotulo do campo de descricao da regra - campo opcional
		s.Add(wx.StaticText(self, label=_("Descrição (opcional):")),
			flag=wx.LEFT | wx.TOP, border=8)
		self._descricao = wx.TextCtrl(self)
		s.Add(self._descricao, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)

		ok = wx.Button(self, wx.ID_OK, _("&Confirmar"))
		ok.SetDefault()
		ca = wx.Button(self, wx.ID_CANCEL, _("Cancelar"))
		bs = wx.StdDialogButtonSizer()
		bs.AddButton(ok)
		bs.AddButton(ca)
		bs.Realize()
		s.Add(bs, flag=wx.ALIGN_CENTER | wx.BOTTOM, border=8)

		self.SetSizer(s)
		s.Fit(self)
		ok.Bind(wx.EVT_BUTTON, self._ok)
		ca.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_CANCEL))
		self.Bind(wx.EVT_CHAR_HOOK, self._key)
		self.Bind(wx.EVT_SHOW, lambda e: self._tipo.SetFocus() if e.IsShown() else None)

	def _key(self, e):
		if e.GetKeyCode() == wx.WXK_ESCAPE:
			self.EndModal(wx.ID_CANCEL)
		else:
			e.Skip()

	def _ok(self, e):
		self.tipo = self._tipo.GetSelection()
		self.direcao = self._direcao.GetSelection()
		self.porta = self._porta.GetValue().strip()
		self.protocolo = self._proto.GetStringSelection() or "TCP"
		self.programa = self._programa.GetValue().strip()
		self.ip_remoto = self._ip.GetValue().strip()
		self.acao = self._acao.GetSelection()
		self.perfil_dominio = self._perfil_dominio.GetValue()
		self.perfil_privado = self._perfil_privado.GetValue()
		self.perfil_publico = self._perfil_publico.GetValue()
		self.nome = self._nome.GetValue().strip()
		self.descricao = self._descricao.GetValue().strip()
		self.EndModal(wx.ID_OK)


class TargetParamDialog(wx.Dialog):
	"""Dialogo com um campo obrigatorio (alvo/destino), um campo
	numerico opcional (um parametro como quantidade de pacotes ou limite
	de saltos) e, opcionalmente, um SEGUNDO parametro opcional (usado pelo
	Ping, pra porta TCP, e pelo Traceroute, pra escolher IPv4/IPv6/
	automatico). Reaproveitado por Ping e Traceroute - os dois pedem um
	destino mais um numero que ja tem um valor padrao razoavel. Os campos
	de parametro comecam em branco de proposito (nao pre-preenchidos com
	o padrao): se o usuario deixar em branco ou digitar algo invalido,
	quem chamou o dialogo usa o padrao normal - o dialogo em si so
	devolve o texto cru digitado, sem validar numero.

	param2_label (opcional): quando informado, adiciona um TERCEIRO
	campo de texto opcional ao dialogo - hoje so o Traceroute usa
	(escolha de protocolo). Quando None, o dialogo fica exatamente como
	sempre foi - self.param2 continua existindo mas fica sempre "", sem
	nenhum campo extra na tela."""

	def __init__(self, parent, title, target_label, target_default, param_label, param2_label=None):
		super().__init__(parent, title=title)
		self.target = ""
		self.param = ""
		self.param2 = ""
		s = wx.BoxSizer(wx.VERTICAL)
		def _f(lbl, val):
			s.Add(wx.StaticText(self, label=lbl), flag=wx.LEFT | wx.TOP, border=8)
			c = wx.TextCtrl(self, value=val)
			s.Add(c, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)
			return c
		self._target = _f(target_label, target_default)
		self._param = _f(param_label, "")
		self._param2 = _f(param2_label, "") if param2_label else None
		ok = wx.Button(self, wx.ID_OK, _("&Confirmar"))
		ok.SetDefault()
		ca = wx.Button(self, wx.ID_CANCEL, _("Cancelar"))
		bs = wx.StdDialogButtonSizer()
		bs.AddButton(ok)
		bs.AddButton(ca)
		bs.Realize()
		s.Add(bs, flag=wx.ALIGN_CENTER | wx.ALL, border=8)
		self.SetSizer(s)
		s.Fit(self)
		ok.Bind(wx.EVT_BUTTON, self._ok)
		ca.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_CANCEL))
		self.Bind(wx.EVT_CHAR_HOOK, self._key)
		self.Bind(wx.EVT_SHOW, lambda e: self._target.SetFocus() if e.IsShown() else None)

	def _key(self, e):
		if e.GetKeyCode() == wx.WXK_ESCAPE:
			self.EndModal(wx.ID_CANCEL)
		else:
			e.Skip()

	def _ok(self, e):
		self.target = self._target.GetValue().strip()
		self.param = self._param.GetValue().strip()
		if self._param2 is not None:
			self.param2 = self._param2.GetValue().strip()
		self.EndModal(wx.ID_OK)


class MenuDialog(wx.Dialog):
	"""Menu principal em lista, aberto com NVDA+Shift+R.

	Recebe a lista de itens (par id_estavel/rotulo_traduzido) de quem
	instancia, em vez de conhece-la diretamente - assim este arquivo nao
	precisa saber nada sobre quais funcionalidades existem, so sobre como
	desenhar um menu.

	iface_tabs (opcional): quando informado, adiciona uma faixa de abas
	(wx.Notebook) no TOPO do dialogo, antes da lista de acoes - uma aba
	por adaptador de rede, mais "Automatico" - para trocar de interface
	com Ctrl+Tab/Ctrl+Shift+Tab ou as setas, igual as abas de
	Entrada/Saida do Firewall. Trocar de aba aplica a escolha na hora via
	on_iface_change, sem precisar confirmar nada. O foco inicial continua
	sendo a lista de acoes (comportamento de sempre); a faixa de abas fica
	antes dela na ordem de navegacao, entao Shift+Tab a partir da lista
	chega ate ela. So o menu principal usa isso; os submenus (DNS/IPv6/
	Firewall) continuam chamando MenuDialog sem esses parametros extras,
	do jeito de sempre.

	on_iface_change pode devolver uma lista nova de itens (id, rotulo) -
	quando devolve algo que nao e None, a lista de acoes visivel e
	repopulada na hora (usado hoje para esconder "Informacoes e Senha
	Wi-Fi" quando a interface selecionada claramente nao e Wi-Fi). Se o
	callback nao devolver nada (None), a lista de acoes fica como estava.
	"""

	def __init__(self, parent, title, menu_items, iface_tabs=None,
			initial_tab_index=0, on_iface_change=None):
		super().__init__(parent, title=title)
		self.chosen = None
		s = wx.BoxSizer(wx.VERTICAL)

		self._nb = None
		self._tab_ids = []
		self._on_iface_change = on_iface_change
		if iface_tabs:
			# translators: instrucao de uso da faixa de abas de interface de rede (aparece so no menu principal)
			s.Add(wx.StaticText(self,
				label=_("Interface de Rede (Ctrl+Tab para alternar):")),
				flag=wx.LEFT|wx.RIGHT|wx.TOP, border=6)
			self._nb = wx.Notebook(self)
			self._tab_ids = [tid for tid, _label in iface_tabs]
			for _tid, label in iface_tabs:
				self._nb.AddPage(wx.Panel(self._nb), label)
			if 0 <= initial_tab_index < len(iface_tabs):
				self._nb.SetSelection(initial_tab_index)
			s.Add(self._nb, flag=wx.EXPAND|wx.ALL, border=6)
			self._nb.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGED, self._on_page_changed)

		# translators: instrucao de uso mostrada acima da lista de acoes do menu
		s.Add(wx.StaticText(self,
			label=_("Setas para navegar, Enter para ativar, Escape para fechar:")),
			flag=wx.ALL, border=6)
		self._lb = wx.ListBox(self, style=wx.LB_SINGLE)
		self._map = []
		for item_id, label in menu_items:
			self._lb.Append(label)
			self._map.append(item_id)
		self._lb.SetSelection(0)
		self._lb.SetMinSize((420, 320))
		s.Add(self._lb, 1, wx.EXPAND|wx.ALL, 6)

		btn = wx.Button(self, wx.ID_CANCEL, _("&Fechar"))
		s.Add(btn, flag=wx.ALIGN_CENTER|wx.BOTTOM, border=8)
		self.SetSizer(s)
		s.Fit(self)
		# EVT_CHAR_HOOK captura teclas antes do wx processar internamente,
		# o que garante que Enter/Espaco funcionem mesmo com o NVDA activo
		self.Bind(wx.EVT_CHAR_HOOK, self._key)
		self._lb.Bind(wx.EVT_KEY_DOWN, self._key)
		btn.Bind(wx.EVT_BUTTON, lambda e: self.EndModal(wx.ID_CANCEL))
		# Foco inicial continua na lista de acoes (comportamento de
		# sempre) mesmo com a faixa de abas vindo antes dela na ordem de
		# navegacao - assim quem so quer escolher uma acao nao percebe
		# diferenca nenhuma, e quem quer trocar de interface chega la com
		# um Shift+Tab.
		self.Bind(wx.EVT_SHOW, lambda e: self._lb.SetFocus() if e.IsShown() else None)

	def _on_page_changed(self, e):
		idx = e.GetSelection()
		if self._on_iface_change and 0 <= idx < len(self._tab_ids):
			new_items = self._on_iface_change(self._tab_ids[idx])
			if new_items is not None:
				self._set_menu_items(new_items)
		e.Skip()

	def _set_menu_items(self, menu_items):
		"""Repopula a lista de acoes com uma lista nova de (id, rotulo).
		Preserva a selecao pelo id_estavel quando o item ainda existe na
		lista nova (ex.: trocou de Ethernet para outra interface nao-Wi-Fi,
		o item selecionado continua existindo) - assim o usuario nao perde
		o lugar onde estava por causa de uma troca de aba. Se o item que
		estava selecionado sumiu (ex.: estava em "Informacoes e Senha
		Wi-Fi" e a nova interface nao e Wi-Fi), volta pro topo da lista em
		vez de deixar a selecao invalida."""
		prev_sel = self._lb.GetSelection()
		prev_id = self._map[prev_sel] if prev_sel != wx.NOT_FOUND else None
		self._lb.Clear()
		self._map = []
		for item_id, label in menu_items:
			self._lb.Append(label)
			self._map.append(item_id)
		if prev_id is not None and prev_id in self._map:
			self._lb.SetSelection(self._map.index(prev_id))
		elif self._map:
			self._lb.SetSelection(0)

	def _key(self, e):
		kc = e.GetKeyCode()
		if kc in (wx.WXK_RETURN, wx.WXK_NUMPAD_ENTER, wx.WXK_SPACE):
			# So ativa um item da lista se o foco nao estiver na faixa de
			# abas - senao Enter/Espaco enquanto o usuario esta so
			# trocando de adaptador dispararia uma acao por engano.
			if self._nb is not None and self.FindFocus() is self._nb:
				e.Skip()
				return
			idx = self._lb.GetSelection()
			if idx != wx.NOT_FOUND:
				self.chosen = self._map[idx]
				self.EndModal(wx.ID_OK)
		elif kc == wx.WXK_ESCAPE:
			self.EndModal(wx.ID_CANCEL)
		else:
			e.Skip()
