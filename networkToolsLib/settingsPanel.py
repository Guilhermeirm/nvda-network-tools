# -*- coding: utf-8 -*-
# Painel de configuracoes do Network Tools, integrado em Preferencias >
# Configuracoes do NVDA (categoria "Network Tools" na lista a esquerda).
# Cada campo aqui e so a INTERFACE - o valor persistido de verdade mora
# em config.conf["networkTools"], cujo schema (confspec) e registrado em
# globalPlugins/networkTools.py junto com o resto da configuracao ja
# existente do complemento (selectedInterface).
#
# A documentacao oficial da NVDA e explicita: initTranslation() deve ser
# chamado "no topo de CADA modulo Python" do addon, nao uma vez so no
# arquivo principal - cada modulo precisa da propria chamada pra ter
# _() de verdade. Confirmado ao vivo: o painel de Configuracoes
# aparecia sempre em portugues, mesmo com a NVDA configurada e
# reiniciada em espanhol - porque este arquivo nunca chamava
# initTranslation() por conta propria, so contava com uma suposicao
# (capturar uma copia do builtin) que se provou incorreta na pratica.

import addonHandler
addonHandler.initTranslation()

import wx
from gui import guiHelper, nvdaControls
from gui.settingsDialogs import SettingsPanel
import config
from . import netinfo as net

class NetworkToolsSettingsPanel(SettingsPanel):
	# translators: titulo da categoria do Network Tools em Preferencias > Configuracoes do NVDA
	title = _("Network Tools")

	def makeSettings(self, settingsSizer):
		helper = guiHelper.BoxSizerHelper(self, sizer=settingsSizer)
		conf = config.conf["networkTools"]

		# translators: opcao para iniciar o Monitor de Conexao automaticamente quando o NVDA inicia
		self._autoStart = helper.addItem(
			wx.CheckBox(self, label=_("&Iniciar o Monitor de Conexão automaticamente com o NVDA")))
		self._autoStart.SetValue(conf["monitorAutoStart"])

		self._interval = helper.addLabeledControl(
			# translators: rotulo do campo de intervalo de verificacao do Monitor de Conexao, em segundos
			_("I&ntervalo de verificação do Monitor (segundos):"),
			nvdaControls.SelectOnFocusSpinCtrl,
			min=3, max=300, initial=conf["monitorInterval"])

		# net.speedtest_sizes() - fonte UNICA de verdade compartilhada com
		# o Teste de Velocidade em si (globalPlugins/networkTools.py). Ver
		# o comentario na propria funcao para o motivo de nao duplicar
		# essa lista aqui como antes (as duas copias tinham dessincronizado
		# na pratica).
		self._speedtestSizes = net.speedtest_sizes()
		speedtest_labels = [label for _sid, label, _d, _u in self._speedtestSizes]
		self._speedtestChoice = helper.addLabeledControl(
			# translators: rotulo do campo de tamanho padrao do Teste de Velocidade
			_("&Tamanho padrão do Teste de Velocidade:"),
			wx.Choice, choices=speedtest_labels)
		ids = [sid for sid, _label, _d, _u in self._speedtestSizes]
		try:
			self._speedtestChoice.SetSelection(ids.index(conf["speedtestDefaultSize"]))
		except ValueError:
			self._speedtestChoice.SetSelection(1)  # "medium" - preset padrao de fabrica

		self._speedtestConnections = helper.addLabeledControl(
			# translators: rotulo do campo de conexoes paralelas do preset Grande do Teste de Velocidade
			_("Conexões paralelas no preset &Grande do Teste de Velocidade:"),
			nvdaControls.SelectOnFocusSpinCtrl,
			min=1, max=8, initial=conf["speedtestConnections"])

		self._pingCount = helper.addLabeledControl(
			# translators: rotulo do campo de quantidade padrao de pacotes do Ping
			_("Quantidade padrão de pacotes do &Ping:"),
			nvdaControls.SelectOnFocusSpinCtrl,
			min=1, max=1000, initial=conf["pingDefaultCount"])

		self._tracertHops = helper.addLabeledControl(
			# translators: rotulo do campo de limite padrao de saltos do Traceroute
			_("Limite padrão de &saltos do Traceroute:"),
			nvdaControls.SelectOnFocusSpinCtrl,
			min=1, max=64, initial=conf["tracertDefaultHops"])

		self._dnsTimeout = helper.addLabeledControl(
			# translators: rotulo do campo de tempo limite por servidor na Busca de Melhor DNS, em segundos
			_("Tempo limite por servidor na Busca de Melhor &DNS (segundos):"),
			nvdaControls.SelectOnFocusSpinCtrl,
			min=1, max=10, initial=conf["dnsBestTimeout"])

		self._dnsSamples = helper.addLabeledControl(
			# translators: rotulo do campo de quantidade de consultas por servidor na Busca de Melhor DNS (para medir estabilidade, nao so velocidade)
			_("Consultas por servidor na Busca de Melhor D&NS (estabilidade):"),
			nvdaControls.SelectOnFocusSpinCtrl,
			min=1, max=20, initial=conf["dnsBestSamples"])

		self._dnsFinalists = helper.addLabeledControl(
			# translators: rotulo do campo de quantidade de servidores no ranking final (finalistas) da Busca de Melhor DNS
			_("Quantidade de servidores no &ranking da Busca de Melhor DNS:"),
			nvdaControls.SelectOnFocusSpinCtrl,
			min=1, max=20, initial=conf["dnsBestFinalists"])

		self._dnsTestOneSamples = helper.addLabeledControl(
			# translators: rotulo do campo de quantidade de consultas no teste avulso de um unico servidor DNS (separado da Busca de Melhor DNS)
			_("Consultas no &Teste de um Servidor DNS avulso:"),
			nvdaControls.SelectOnFocusSpinCtrl,
			min=1, max=50, initial=conf["dnsTestOneSamples"])

		self._dnsTestOneTimeout = helper.addLabeledControl(
			# translators: rotulo do campo de tempo limite no teste avulso de um unico servidor DNS (separado da Busca de Melhor DNS), em segundos
			_("Tempo limite no Teste de um Servidor DNS a&vulso (segundos):"),
			nvdaControls.SelectOnFocusSpinCtrl,
			min=1, max=10, initial=conf["dnsTestOneTimeout"])

	def onSave(self):
		conf = config.conf["networkTools"]
		conf["monitorAutoStart"] = self._autoStart.GetValue()
		conf["monitorInterval"] = self._interval.GetValue()
		ids = [sid for sid, _label, _d, _u in self._speedtestSizes]
		conf["speedtestDefaultSize"] = ids[self._speedtestChoice.GetSelection()]
		conf["speedtestConnections"] = self._speedtestConnections.GetValue()
		conf["pingDefaultCount"] = self._pingCount.GetValue()
		conf["tracertDefaultHops"] = self._tracertHops.GetValue()
		conf["dnsBestTimeout"] = self._dnsTimeout.GetValue()
		conf["dnsBestSamples"] = self._dnsSamples.GetValue()
		conf["dnsBestFinalists"] = self._dnsFinalists.GetValue()
		conf["dnsTestOneSamples"] = self._dnsTestOneSamples.GetValue()
		conf["dnsTestOneTimeout"] = self._dnsTestOneTimeout.GetValue()
