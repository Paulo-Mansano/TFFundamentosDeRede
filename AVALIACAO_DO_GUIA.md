# Avaliação do *Guia de Execução e Plano Técnico* do grupo

> Documento de revisão técnica do arquivo `Guia_Tecnico_TF_Redes_MITM.pdf`,
> confrontado com o enunciado oficial (`TF_20262_mitm.pdf`) e com a
> implementação de referência construída neste repositório (que, ao ser
> efetivamente executada, revelou na prática quais pontos do guia estavam
> corretos e quais precisavam de reforço).

## Veredito geral

**O guia é muito bom.** Ele cumpre exatamente o papel a que se propõe: traduz o
enunciado em um plano de ação, mapeia cada critério de avaliação para a
habilidade cobrada, propõe uma arquitetura concorrente coerente (duas frentes +
fila thread-safe) e um faseamento realista. A cobertura dos requisitos do
enunciado é **completa** — todos os itens da Seção 8 (avaliação) têm
contrapartida no guia. Como material de estudo e planejamento, está acima da
média.

A ressalva importante é que **os trechos de código são esqueletos** (o próprio
guia avisa isso). Ao transformá-los em código que roda de verdade, há um
conjunto de detalhes técnicos — a maioria *não mencionada* no guia — que
separam "parece funcionar" de "funciona". Esses detalhes são justamente os que
caem na arguição individual. A lista abaixo é o principal valor desta revisão.

---

## Pontos fortes (manter)

1. **Mapa avaliação → habilidade → evidência (Tabelas 1 e 2).** Excelente para
   distribuir esforço e para a autoavaliação antes da entrega.
2. **Arquitetura de concorrência (Figuras 2 e 5).** A separação captura →
   fila → processamento, com spoofer e painel em paralelo e estado sob lock, é
   a decisão de projeto correta e foi adotada integralmente na implementação.
3. **Faseamento incremental com "pronto quando".** Cada fase entrega algo
   demonstrável — a melhor defesa contra o "tudo pela metade".
4. **Preparação para a arguição (Seção 2.3).** As cinco perguntas-modelo são
   realistas e de alto valor.
5. **Avisos de armadilha corretos:** offsets por IHL/Data Offset, *byte order*
   big-endian, blackhole sem forwarding, DoH ligado por engano, SNI com ECH.
   Todos se confirmaram relevantes.

---

## Correções e lacunas técnicas (reforçar antes de entregar)

Estas são as questões que **só aparecem quando o código roda** e que o guia não
cobre (ou cobre de forma incompleta). Cada uma foi encontrada e resolvida na
implementação de referência.

### 1. Captura duplicada: filtrar `PACKET_OUTGOING` (lacuna)
Um `AF_PACKET`/`ETH_P_ALL` aberto na interface entrega **os dois sentidos**:
o quadro que chega *e a cópia que o próprio atacante reinjeta* ao reencaminhar
(IP forwarding). Sem tratar isso, **cada pacote do fluxo da vítima é
contabilizado em dobro** (contadores inflados, linhas de log repetidas). O guia
não menciona o assunto.
*Solução:* usar `recvfrom()` e descartar os quadros cujo `sll_pkttype ==
PACKET_OUTGOING` (ver `interceptor/app.py::capture_loop`).

### 2. Auto-cura: condição de corrida com o spoofer (lacuna crítica)
O Listing 5 do guia trata o sinal e envia as rajadas corretivas, mas **não
coordena com a thread de spoofing**. Se o `spoof_loop` estiver em
`time.sleep(interval)`, ele acorda e envia **mais uma rajada de envenenamento
depois** das rajadas de correção — re-envenenando o alvo. Na prática, isso fez
o cache do *gateway* **não** se restaurar de forma intermitente.
*Solução:* parar o spoofer com um `threading.Event` e **aguardar (`join`) a
thread terminar antes** de emitir a correção (`interceptor/app.py::_on_signal`).

### 3. Auto-cura: *reply* gratuito não basta; use *ARP Request* de anúncio (correção)
O Linux, por padrão, **não atualiza uma entrada `REACHABLE`** a partir de um
*ARP Reply* não solicitado. As rajadas do Listing 5 (só *replies*) corrigem o
cache de forma pouco confiável. O método robusto é enviar um **gratuitous ARP
*Request* em broadcast** ("who-has real_ip, tell real_ip", SHA = MAC real) —
o mesmo anúncio que um SO faz ao subir a interface; *requests* são processados
e atualizam a entrada do remetente de forma confiável.
*Solução:* `interceptor/arp.py::arp_announce`, usada na `heal()`.

### 4. Estabilidade do MITM: desativar ICMP Redirects (lacuna)
Com o forwarding ligado, o kernel do atacante tende a emitir **ICMP Redirects**
avisando a vítima para falar direto com o gateway — o que *desfaz* o desvio
depois de alguns pacotes. O guia não cita isso.
*Solução:* zerar `net.ipv4.conf.*/send_redirects`
(`interceptor/app.py::disable_icmp_redirects`). Ponto excelente de arguição.

### 5. Parser de SNI: falta robustez e validação de limites (correção)
O Listing 8 está **conceitualmente certo** nos offsets, mas:
   - não valida limites (`len`) a cada passo → quebra com ClientHello truncado;
   - não confere `name_type == 0x00` (host_name) dentro da extensão;
   - assume que o ClientHello cabe em um único *record* TLS.
*Solução:* ver `interceptor/web.py::extract_sni`, com checagem de limites em
todas as leituras.

### 6. Parser de DNS: compressão de nomes nas respostas (lacuna)
O Listing 7 lê o QNAME da *pergunta* (onde não há compressão), mas o enunciado
(3.5) exige **os IPs das respostas** (registros A) para a correlação. Nas
respostas, os nomes usam **ponteiros de compressão** (RFC 1035 §4.1.4); ignorar
isso leva a offsets errados ao caminhar pelos *answers*.
*Solução:* `interceptor/dns.py::_read_name` segue ponteiros (`0xC0`).

### 7. `sys.exit()` no *signal handler* com threads + buffering de stdout (nuance)
`sys.exit()` dentro do handler só levanta `SystemExit` na thread principal; com
daemon threads e I/O em andamento, o encerramento pode ficar sujo e **mensagens
finais podem se perder por buffering**. Convém encerrar com `os._exit(0)` após a
cura e usar saída não-bufferizada (`python -u`/`PYTHONUNBUFFERED`).

### 8. Correlação domínio↔IP: não usar o IP do servidor DNS (nuance)
Ao agregar destinos, é tentador associar o domínio ao `dst` do pacote DNS —
mas esse é o **servidor DNS**, não o site. O "IP de destino associado" (resumo
CSV) deve ser o **IP resolvido** (registro A) ou o destino da conexão
HTTP/HTTPS. O guia não detalha isso e um descuido aqui gera um CSV enganoso.

### 9. Ambiente de execução em Windows (lacuna de contexto)
O guia é — corretamente — centrado em Linux (`AF_PACKET`, `/proc/sys`). Vale
registrar explicitamente que **em Windows isso não roda nativamente**; a
solução reprodutível é um laboratório **Docker** (Cenário A), que este
repositório fornece. Isso evita a armadilha de "não compila/não executa no
ambiente demonstrado".

---

## Pequenos reparos de redação/precisão

- **DoH no Experimento 2:** demonstrar o efeito do DoH exige um *resolver* DoH;
  uma alternativa honesta e suficiente para o sniffer local é forçar resolução
  fora da consulta UDP/53 (ex.: `curl --resolve`). O importante é deixar claro
  no relatório que é *o efeito observável na rede local* (sumiço do UDP/53) que
  está sendo demonstrado, com o SNI permanecendo exposto.
- **"gratuitous/unsolicited ARP" (Seção 3.2):** o envenenamento em si pode usar
  *replies* unicast direcionados (como nos Listings 3), o que inclusive é mais
  furtivo; "gratuitous" se aplica melhor ao *anúncio* da auto-cura (ponto 3).

---

## Conclusão

Seguindo o guia **e** incorporando os nove pontos acima, o grupo tem um trabalho
com nota alta e, mais importante, **com domínio real do porquê de cada decisão**
— que é o que a arguição individual cobra. A implementação de referência neste
repositório já aplica todas essas correções e foi validada ponta a ponta no
laboratório Docker (ver `README.md` e `relatorio/RELATORIO.md`).
