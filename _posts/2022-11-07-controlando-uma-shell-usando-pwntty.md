## Controlando  Shells Usando Pwntty

Salve galera, nesse post irei demonstrar uma ótima e magnifica ferramenta criada pelo @exnorz, o objetivo dela é controlar outros TTY devices, resumidamente podemos controlar outras shells. Supondo que você esteja logado em um SSH, e tem outra pessoa na máquina, essa pessoa pode controlar a sua shell usando o Pwntty ou pode controlar manualmente também, bom agora vamos pra prática! 

Para podermos usar a tool basta colar os seguintes comandos

```
git clone https://github.com/exnorz/pwntty
cd pwntty
python pwntty.py -h
```
![image](/img/pwntty.png)

OBS: Precisamos ser root para podermos usar o pwntty.

O pwntty tem features como

* Controlar devices.
* Mandar mensagens para outros devices.
* Trancar um device, ou seja você não vai conseguir executar nenhum comando, nada do tipo.
* Bug cursor

## Executando comandos em outros devices

Para podermos executar comandos em outros devices, basta especificar usar o seguinte comando

```
sudo python pwntty.py -e id /dev/pts/3
sudo python pwntty.py -e whoami /dev/pts/3
sudo python pwntty.py -e ps /dev/pts/3
```

![image](/img/pwnttycommand.png)

* Mas como podemos identificar em qual PTS esta o outro device?

Bom é bem simples de identificar outros pts, tem várias formas de identificar, alguma delas são

```
ps aux|grep pts
who
w
```

Ou então podemos simplesmente abrir outro terminal e digitar "tty"

* Mas o que esse comando faz?

Bom, ele identifica qual é o seu PTS ( pseudo terminal slave )atual, ou seja qual é o seu device atual.

Depois que identificar qual é o PTS do outro terminal que você abriu, podemos executar os comandos no qual foi citado acima.

## Mandando mensagem para outros devices.

![image](/img/msgpwntty.png)

Para mandar mensagens em outros devices basta utilizarmos o comando

```
sudo python pwntty.py -m "hello" /dev/pts/3
```

## Trancar/Bloquear devices

![image](/img/locktty.png)

Essa feature é muito apelona, por que você não vai conseguir executar nenhum comando, não vai conseguir executar absolutamente nada.

```
sudo python pwntty.py -l /dev/pts/3
```

## Bug cursor

![image](/img/bugcursor1.png)
![image](/img/bugcursor2.png)

Essa é uma feature muito interessante também. ( agora é so se divertir tiltando os amiguinhos em koth por exemplo hahaha )

```
sudo python pwntty.py -b "blabla" /dev/pts/3
sudo python pwntty.py -b "l" /dev/pts/3
```

Então é basicamente isso que o pwntty faz, é uma ferramenta muito incrivel para poder jogar no KoTH TryHackMe por exemplo, usar a tool contra seus oponentes dentro da máquina.

Bom pessoal eu espero que tenham gostado, obrigado por lerem!! xD

## Curiosidade (Bonus)

* Como funciona a feature de trancar/bloquear devices ?

Bom isso é muito interessante, no codigo do pwntty, podemos ver dois comandos sendo executados na função "lock_tty"

```
exec 2>&-
exec >&-
```

* Mas o que raios é isso ??

Em resumo, "2>&-" fecha o stderrt ( erro padrão ) e ">&-" fecha o stdout ( Saída padrão )
