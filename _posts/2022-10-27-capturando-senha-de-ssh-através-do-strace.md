Bom primeiro precisamos entender o que é o strace.

## O que é o strace ?

O strace é  uma ferramenta de "debugging" ou seja de depuração no linux que serve para depurar um processo em execução, o strace também fornece syscalls (chamada de sistema) que um programa em execução está fazendo e também os seus argumentos.

- Agora que sabemos o que é o strace e o que ele faz, podemos ir para a prática!

## Iniciando um servidor SSH Localmente.

Para iniciarmos um servidor ssh em nossa máquina, basta digitar;

```
sudo service ssh start
```

E pronto, ja temos um servidor ssh rodando em localhost, agora basta se logar na nossa máquina.

```
ssh kali@localhost
```

## Identificando o processo

Bom depois que rodarmos o comando, se a gente usar o ps aux e filtrar por ssh usando o grep, iremos identificar o PID( Process Identifier ) e depois iremos usar o strace.

![image](/img/sshprocess.png)

Identificamos o PID, agora basta usarmos o seguite comando

## Hora do show

```
sudo strace -p 5259 2> testando
```

Mas o que esse comando faz exatamente? Bom vamos lá!

- Para que este "truque" funcione, precisamos ser root, então teremos que rodar o comando como sudo, depois usamos o strace usando o "-p" de pid, ou seja depois que passarmos o parametro "-p" precisamos colocar qual é o PID que identificamos, "2>" para redirecionar todo o output para um arquivo chamado "testando", então é basicamente isso que vai acontecer.

![image](/img/strace.png)

E pronto! agora é so se conectar no ssh colocando nossa senha.

![image](/img/ssh.png)

GG! Agora usando o head (podemos usar o cat em combinação com o grep filtrando pelas syscalls read também, mas o head ele mostra apenas as primeiras linhas, e a nossa senha está na 5 linha na chamada de sistema ou syscall) no nosso output, nossa senha vai aparecer, que no caso é "kali".

```
head testando
```

![image](/img/head.png)

- O que basicamente fizemos foi monitorar/sniffar as syscalls de entrada do ssh.

GG! Então é isso pessoal! Obrigado por lerem! xD
