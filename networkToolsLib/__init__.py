# -*- coding: utf-8 -*-
# networkToolsLib: modulos de apoio do complemento networkTools.
#
# IMPORTANTE sobre a estrutura deste addon:
# O NVDA exige que o PONTO DE ENTRADA do plugin seja um arquivo unico em
# globalPlugins/ (globalPlugins/networkTools.py), sem subpasta/__init__.py
# ali dentro - isso ja foi tentado antes e impediu o NVDA de carregar o
# complemento (o globalPluginHandler varre globalPlugins/ procurando
# modulos com uma classe GlobalPlugin, e uma subpasta-pacote la dentro
# quebra essa deteccao).
#
# Este pacote (networkToolsLib) fica FORA de globalPlugins/, na raiz do
# addon, exatamente para nao ser varrido pelo globalPluginHandler. O
# arquivo globalPlugins/networkTools.py insere a raiz do addon no
# sys.path e importa daqui normalmente - a mesma tecnica usada por outros
# complementos do NVDA para empacotar bibliotecas auxiliares (ex.:
# addons que trazem "requests", "chardet" etc. em uma pasta propria).
