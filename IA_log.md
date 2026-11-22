# Registro de Uso de Inteligência Artificial

> Seção obrigatória (enunciado, Seção 6). Preencham/ajustem com os usos reais do
> grupo. Abaixo está um registro-base honesto do que foi feito na construção
> desta implementação de referência, para o grupo adaptar e assumir a autoria
> crítica. **Lembrete:** a autoria técnica e a compreensão são de vocês e serão
> cobradas individualmente na arguição.

## Ferramentas e modelos

- Assistente de IA (modelo de linguagem) — apoio em concepção, implementação,
  depuração e análise.
- *(adicionar outras ferramentas que o grupo tenha usado: ChatGPT, Copilot,
  Cursor, Gemini, etc.)*

## Como a IA foi empregada, por etapa

| Etapa | Uso da IA | Avaliação crítica do grupo |
|-------|-----------|----------------------------|
| Leitura de RFCs | Resumir a estrutura do TLS ClientHello e da mensagem DNS | Conferimos os offsets byte a byte contra a captura real; a IA acertou a sequência, mas **não** lembrou de validar limites nem da compressão de nomes no DNS. |
| Arquitetura | Validar o modelo threads + fila + lock | Coerente com o guia; adotado. |
| Depuração | Explicar por que o cache do gateway não restaurava | A IA sugeriu checar a condição de corrida com o spoofer e o comportamento do Linux com *replies* não solicitados — confirmado empiricamente. |
| Ambiente | Montar o laboratório Docker isolado | Ajustes manuais de rotas/redes foram necessários. |
| Testes | Estruturar os testes de unidade dos parsers | Úteis para isolar bugs sem subir o laboratório. |

## Exemplos de prompts (representativos)

1. *"Qual a ordem exata dos campos do TLS ClientHello até a extensão SNI e como
   calcular os offsets?"* — resposta correta na sequência; complementamos com
   checagem de limites.
2. *"Por que o Linux ignora meu ARP reply gratuito ao restaurar o cache?"* —
   levou ao uso de **gratuitous ARP request** (anúncio), que resolveu.
3. *"Como evitar contar o mesmo pacote duas vezes num raw socket que também vê o
   tráfego reencaminhado?"* — levou ao filtro de `PACKET_OUTGOING`.

## Dificuldades / respostas incorretas ou incompletas

- A IA inicialmente **não** mencionou a necessidade de desativar ICMP Redirects;
  descobrimos o problema observando o desvio "cair" após alguns pacotes.
- O esqueleto de parser de SNI sugerido não tinha verificação de limites —
  adicionamos para não quebrar com pacotes truncados.
- Em DNS, a extração de IPs nas respostas exigiu tratar **compressão de nomes**,
  detalhe que precisou ser pedido explicitamente.

## Conclusão

A IA acelerou a leitura de RFCs e a depuração, mas **todas** as decisões foram
verificadas contra a captura real (Wireshark/tcpdump) e os testes de unidade. Os
pontos mais sutis (corrida na auto-cura, ARP announce, duplicação de captura,
ICMP redirects, compressão DNS) só se fecharam com observação empírica —
reforçando que o domínio do funcionamento é do grupo.
