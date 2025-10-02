# PROPOSTA:
## Nesse projeto foi proposto pela FIAP em parceria com a PRIDE SECURITIES que fosse feito um código que impediria um ransomware de rodar em sua máquina.

# OBS:
## Os códigos monitoramento.py e monitoramento2.py foram os primeiros códigos feitos ou seja, são mais simples e de entropia é o código em andamento, já o ramsonware.py é um simulador de ransomware seguro que criptografa somente na pasta em que ele está. (USE O SIMULADOR EM UMA PASTA SEPARADA)

## Explicação do código:
# O código consiste em basicamente em 3 partes o monitoramento das pastas principais como desktop e downloads para identificar atividades suspeitas como processos com CPU elevadas, criptografia e a eliminação rápida de arquivos.
# A criação de honeypots para que o ransomware "morda a isca".
# E por último e eliminação desse processo onde o programa identifica qual é o processo que está causando essa criptografia, criação e/ou eliminação de arquivos.
# Foi feito uma interface gráfica como pode ser visto no arquivo app.py de forma bem simples que funciona da seguinte maneira, existem dois endpoints o /start e o /logs, sendo o primeiro para iniciar a aplicação e o segundo para observar o que de fato está acontecendo.
# Aceito melhorias de código, e formas de como testar o código de forma mais eficiente e confiável.
