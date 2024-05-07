; Antonio Augusto Dantas Neto
; Deivily Breno Silva Carneiro
; Lucas Gabriel Fontes da Silva

.686
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc 
include \masm32\include\kernel32.inc 
include \masm32\include\masm32.inc 
includelib \masm32\lib\kernel32.lib 
includelib \masm32\lib\masm32.lib 

.data? ; BSS

    bytesLidos dd ? ARMAZENA A QUANTIDADE BYTES LIDOS NO ARQUIVO DE ENTRADA
    bytesEscritos dd ? ; ARMAZENA A QUANTIDADE DE BYTES ESCRITOS NO ARQUIVO DE SAIDA
    escolhaUsuario dd ? ; ARMAZENA A OPCAO ESCOLHIDA PELO USUARIO (1, 2, OU 3)

.data ; DATA

    handleEntradaConsole dd 0
    handleSaidaConsole dd 0
    handleEntradaArquivo dd 0
    handleSaidaArquivo dd 0
    bufferEntrada db 53 DUP(0)
    bufferSaida db 53 DUP(0)
    bufferChave db 11 DUP(0)
    chaveDWORD dd 8 dup(0) ; CRIA UM ARRAY DE 8 DWORDs QUE VAI CONTER OS REPRESENTANTES INTEIROS DOS BYTES DE BUFFERCHAVE
    
    menuString db 0AH, "Menu de Opcoes:", 0AH, 0H
    opcao1 db "1. Criptografar", 0AH, 0H
    opcao2 db "2. Descriptografar", 0AH, 0H
    opcao3 db "3. Sair", 0AH, 0H
    escolha db 0AH, "Escolha uma opcao: ", 0H
    promptEntrada db 0AH, "Digite o nome do arquivo de entrada: ", 0H
    promptSaida db 0AH, "Digite o nome do arquivo de saida: ", 0H
    promptChave db 0AH, "Digite a chave de criptografia: ", 0H
    promptEncerrar db 0AH, "Obrigado por usar o nosso programa de Cifra de transposicao! Adeus!", 0AH, 0H
    promptOpcaoInvalida db 0AH, "Opcao invalida! Digite 1, 2 ou 3!", 0AH, 0H

.code ; INSTRUCOES

funcoes: ; FUNCOES DO CODIGO

menu_mensagens:
    ; NAO RECEBE NENHUM PARAMETRO, APENAS EXIBE AS 3 OPCOES DO MENU
    push ebp
    mov ebp, esp
    invoke WriteConsole, handleSaidaConsole, addr menuString, sizeof menuString - 1, addr bytesLidos, NULL
    invoke WriteConsole, handleSaidaConsole, addr opcao1, sizeof opcao1 - 1, addr bytesLidos, NULL
    invoke WriteConsole, handleSaidaConsole, addr opcao2, sizeof opcao2 - 1, addr bytesLidos, NULL
    invoke WriteConsole, handleSaidaConsole, addr opcao3, sizeof opcao3 - 1, addr bytesLidos, NULL
    invoke WriteConsole, handleSaidaConsole, addr escolha, sizeof escolha - 1, addr bytesLidos, NULL
    mov esp, ebp
    pop ebp
    ret

; FUNCAO QUE CRIPTOGRAFA
criptografar:

    ; CRIA UMA NOVA MOLDURA DE PILHA
    push ebp
    mov ebp, esp

    ; OBTEM OS ARGUMENTOS DA PILHA
    mov esi, [ebp+8] ; BUFFER DE ENTRADA 
    mov edi, [ebp+12] ; BUFFER DE SAIDA
    mov edx, [ebp+16] ; CHAVE

    ; INICIALIZA O CONTADOR
    xor ecx, ecx

    laco_criptografia:
        ; VERIFICA SE TODOS OS BYTES FORAM PROCESSADOS
        cmp ecx, 8
        jge fim_laco_criptografia

        ; OBTEM A POSICAO ATUAL DA CHAVE
        mov eax, [edx + ecx * 4]

        ; OBTEM O BYTE ATUAL DO BUFFER DE ENTRADA
        movzx ebx, BYTE PTR [esi + ecx]

        ; COLOCA O BYTE NA POSICAO CORRESPONDENTE DO BUFFER DE SAIDA
        mov [edi + eax], bl

        ; INCREMENTA O CONTADOR
        inc ecx

        ; VERIFICA SE JA PROCESSOU TODOS OS BYTES
        cmp ecx, [bytesLidos]
        jl laco_criptografia

    fim_laco_criptografia:
        ; RESTAURA A MOLDURA DE PILHA ANTERIOR
        mov esp, ebp
        pop ebp
        ret 12

; FUNCAO QUE DESCRIPTOGRAFA
descriptografar:

    ; CRIA UMA NOVA MOLDURA DE PILHA
    push ebp
    mov ebp, esp

    ; OBTEM OS ARGUMENTOS DA PILHA
    mov esi, [ebp+8] ; BUFFER DE ENTRADA
    mov edi, [ebp+12] ; BUFFER DE SAIDA
    mov edx, [ebp+16] ; CHAVE

    ; INICIALIZA O CONTADOR
    xor ecx, ecx

    laco_descriptografia:
        ; VERIFICA SE TODOS OS BYTES FORAM PROCESSADOS
        cmp ecx, 8
        jge fim_laco_descriptografia

        ; OBTEM A POSICAO ATUAL DA CHAVE
        mov eax, [edx + ecx * 4]

        ; OBTEM O BYTE NA POSICAO ESPECIFICADA PELA CHAVE DO BUFFER DE ENTRADA
        movzx ebx, BYTE PTR [esi + eax]

        ; COLOCA O BYTE NA POSICAO ATUAL DO BUFFER DE SAIDA
        mov [edi + ecx], bl

        ; INCREMENTA O CONTADOR
        inc ecx

        ; VERIFICA SE JA PROCESSOU TODOS OS BYTES
        cmp ecx, [bytesLidos]
        jl laco_descriptografia

    fim_laco_descriptografia:
        ; RESTAURA A MOLDURA DE PILHA ANTERIOR
        mov esp, ebp
        pop ebp
        ret 12

processarArquivo:
    
    ; CRIA UMA NOVA MOLDURA DE PILHA
    push ebp
    mov ebp, esp

    ; LOOP PARA LER E ESCREVER 8 BYTES DE CADA VEZ NO ARQUIVO DE SAIDA
    leitura_escrita_loop:

    ; INICIALIZA O BUFFER DE SAIDA COM ZEROS
    mov ecx, 8 ; TAMANHO DO BUFFER DE SAIDA (8 bytes)
    mov edi, offset bufferSaida ; ENDERECO DO BUFFER DE SAIDA
    xor al, al ; VALOR ZERO

    ; LOOP PARA PREENCHER O BUFFER DE SAIDA COM ZEROS
    preencher_bufferSaida:
        mov [edi], al ; PREENCHE O BYTE ATUAL COM ZERO
        inc edi ; AVANCA PARA O PROXIMO BYTE 
        dec ecx ; DECREMENTA O CONTADOR DE BYTES
        cmp ecx, 0 ; COMPARA O CONTADOR DE BYTES COM ZERO 
        jne preencher_bufferSaida ; SE FOR DIFERENTE DE ZERO, CONTINUA O LOOP

    fim_preencher_bufferSaida:

    ; LE 8 BYTES DO ARQUIVO DE ENTRADA
    invoke ReadFile, handleEntradaArquivo, addr bufferEntrada, 8, addr bytesLidos, NULL

    mov eax, [ebp + 8] ; ARMAZENA A OPCAO ESCOLHIDA PELO USUARIO NO REGISTRADOR EAX

    ; VERIFICA SE O FINAL DO ARQUIVO FOI ALCANCADO
    cmp bytesLidos, 0
    je fim_leitura_escrita

    processar_dados:
    ; CHAMA A FUNCAO DE CRIPTOGRAFIA OU DESCRIPTOGRAFIA DEPENDENDO DO PARAMETRO
    cmp eax, 1 ; COMPARA COM 1
    je criptografar_dados
    cmp eax, 2 ; COMPARA COM 2
    je descriptografar_dados

    criptografar_dados:
    push offset chaveDWORD ; EMPILHA O ENDERECO DO ARRAY chaveDWORD
    push offset bufferSaida ; EMPILHA O ENDERECO DO bufferSaida
    push offset bufferEntrada ; EMPILHA O ENDERECO DO bufferEntrada
    call criptografar ; CHAMA A FUNCAO CRIPTOGRAFAR
    jmp escrever_dados

    descriptografar_dados:
    push offset chaveDWORD ; EMPILHA O ENDERECO DO ARRAY CHAVEDWOR
    push offset bufferSaida ; EMPILHA O ENDERECO DO bufferSaida
    push offset bufferEntrada ; EMPILHA O ENDERECO DO BUFFERENTRADA 
    call descriptografar ; CHAMA A FUNCAO DESCRIPTOGRAFAR 

    escrever_dados:
    ; ESCREVE OS BYTES LIDOS NO ARQUIVO DE SAIDA
    invoke WriteFile, handleSaidaArquivo, addr bufferSaida, 8, addr bytesEscritos, NULL
    
    ; CONTINUAR O LOOP
    jmp leitura_escrita_loop

    fim_leitura_escrita:
    ; RESTAURA A MOLDURA DE PILHA ANTERIOR
    mov esp, ebp
    pop ebp
    ret 4

; FUNCAO PARA CONVERTER PARA TRATAR STRING
removeCR:
    ; CRIA UMA NOVA MOLDURA DE PILHA
    push ebp
    mov ebp, esp

    ; O BUFFER DE ENTRADA E PASSADO COMO UM ARGUMENTO NA PILHA
    mov esi, [ebp+8] ; ARMAZENA O APONTADOR DA STRING EM ESI

    proximo:
        mov al, [esi] ; MOVE O CARACTERE ATUAL PARA AL
        inc esi ; APONTA PARA O PROXIMO CARACTERE
        cmp al, 13 ; VERIFICA SE E O CARACTERE ASCII CR - FINALIZAR
        jne proximo ; SE AL FOR DIFERENTE DE 13, VOLTA AO INICIO DO LOOP
    dec esi ; APONTA PARA CARACTERE ANTERIOR, ONDE CR FOI ENCONTRADO
    xor al, al ; ASCII 0, TERMINADOR DE STRING
    mov [esi], al ; INSERE O ASCII 0 NO LUGAR DO ASCII CR

    ; RESTAURA A MOLDURA DE PILHA ANTERIOR
    mov esp, ebp
    pop ebp
    ret 4
    
; FUNCAO PARA CONVERTER PARA DWORD
converteParaDWORD:
    ; CRIA UMA NOVA MOLDURA DE PILHA
    push ebp
    mov ebp, esp

    ; O BUFFER DE ENTRADA EH PASSADO COMO UM ARGUMENTO NA PILHA
    invoke atodw, [ebp+8]
    mov [ebp-4], eax

    ; RESTAURA A MOLDURA DE PILHA ANTERIOR
    mov eax, [ebp-4]
    mov esp, ebp
    pop ebp
    ret 4

; FUNCAO PARA CONVERTER ARRAY DE CARACTERES PARA ARRAY DE DWORDS
converteChaveParaDWORD:
    ; CRIAR UMA NOVA MOLDURA DE PILHA
    push ebp
    mov ebp, esp

    ; RECEBE COMO PARAMETRO O ENDERECO DO ARRAY DE CARACTERES E O ENDERECO DO ARRAY DE DWORDS
    mov esi, [ebp+8] ; APONTADOR PARA ARRAY DE CARACTERES
    mov edi, [ebp+12] ; APONTADOR PARA BUFFERCHAVE

    ; INICIALIZA O CONTADOR
    xor ecx, ecx

    laco_conversao:
        ; VERIFICA SE TODOS OS CARACTERES FORAM PROCESSADOS
        cmp ecx, 8
        jge fim_laco_conversao

        ; OBTEM O CARACTERE ATUAL
        movzx eax, BYTE PTR [edi + ecx]

        ; SUBTRAI 48 DO CODIGO ASCII PARA OBTER O VALOR NUMERICO
        sub eax, 48

        ; ARMAZENA O VALOR NUMERICO NO ARRAY DE DWORDS
        mov DWORD PTR [esi + ecx * 4], eax

        ; INCREMENTA O CONTADOR
        inc ecx

        ; VOLTA PARA O INICIO DO LOOP
        jmp laco_conversao

    fim_laco_conversao:
        ; RESTAURA A MOLDURA DE PILHA ANTERIOR
        mov esp, ebp
        pop ebp
        ret 8

start: ; INICIO DAS INTRUCOES

    ; OBTEM O HANDLE DO CONSOLE DE ENTRADA
    invoke GetStdHandle, STD_INPUT_HANDLE
    mov handleEntradaConsole, eax

    ; OBTEM O HANDLE DO CONSOLE DE SAIDA
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov handleSaidaConsole, eax

    ; ESCREVE O MENU DE OPCOES NA TELA
    call menu_mensagens

    ; LE A ESCOLHA DO USUARIO
    invoke ReadConsole, handleEntradaConsole, addr bufferEntrada, sizeof bufferEntrada, addr bytesLidos, NULL

    ; REMOVE O CARACTERE DE RETORNO DE CARRO DA ENTRADA DO USUARIO
    push offset bufferEntrada
    call removeCR

    ; CONVERTE A ESCOLHA DO USUARIO PARA DWORD
    push offset bufferEntrada
    call converteParaDWORD; 
    mov escolhaUsuario, eax

    ; PROCESSA A ESCOLHA DO USUARIO
    cmp escolhaUsuario, 3 ; COMPARA COM 3
    je encerrarPrograma
    cmp escolhaUsuario, 1; COMPARA COM 1
    je operacoes_arquivos
    cmp escolhaUsuario, 2; COMPARA COM 2
    je operacoes_arquivos
    invoke WriteConsole, handleSaidaConsole, addr promptOpcaoInvalida, sizeof promptOpcaoInvalida - 1, addr bytesLidos, NULL
    jmp start ; SE NENHUMA DAS OPCOES ACIMA FOR ATENDIDA, VOLTA AO INICIO

    operacoes_arquivos:

        ; SOLICITA O NOME DO ARQUIVO DE ENTRADA
        invoke WriteConsole, handleSaidaConsole, addr promptEntrada, sizeof promptEntrada - 1, addr bytesLidos, NULL
        invoke ReadConsole, handleEntradaConsole, addr bufferEntrada, sizeof bufferEntrada, addr bytesLidos, NULL

        ; TRATA A STRING DE ENTRADA
        push offset bufferEntrada
        call removeCR

        ; SOLICITA O NOME DO ARQUIVO DE SAIDA 
        invoke WriteConsole, handleSaidaConsole, addr promptSaida, sizeof promptSaida - 1, addr bytesLidos, NULL
        invoke ReadConsole, handleEntradaConsole, addr bufferSaida, sizeof bufferSaida, addr bytesLidos, NULL

        ; SOLICITA A CHAVE DE CRIPTOGRAFIA
        invoke WriteConsole, handleSaidaConsole, addr promptChave, sizeof promptChave - 1, addr bytesLidos, NULL
        invoke ReadConsole, handleEntradaConsole, addr bufferChave, sizeof bufferChave, addr bytesLidos, NULL

        ; TRATA A STRING CHAVE
        push offset bufferChave
        call removeCR

        ; CONVERTE A CHAVE ASCII PARA DWORD
        push offset bufferChave
        push offset chaveDWORD ; SUPONDO QUE 'chaveDWORD' SEJA UM ARRAY DE DWORD
        call converteChaveParaDWORD
    
        ; TRATA A STRING DE SAIDA
        push offset bufferSaida
        call removeCR

        ; ABRE O ARQUIVO DE ENTRADA 
        invoke CreateFile, addr bufferEntrada, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
        mov handleEntradaArquivo, eax

        ; ABRE O ARQUIVO DE SAIDA
        invoke CreateFile, addr bufferSaida, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
        mov handleSaidaArquivo, eax

        ; PROCESSA A ESCOLHA DO USUARIO
        cmp escolhaUsuario, 1 ; COMPARA COM 1
        je opcao1_label
        cmp escolhaUsuario, 2 ; COMPARA COM 2
        je opcao2_label
        
        opcao1_label:
            push 1; EMPILHA O PARAMETRO PARA CRIPTOGRAFAR
            call processarArquivo ; CHAMA A FUNCAO processarArquivo
            jmp fim_opcao1_label
        fim_opcao1_label:

        jmp fechar_arquivos

        opcao2_label:
            push 2 ; EMPILHA O PARAMETRO PARA DESCRIPTOGRAFAR
            call processarArquivo ; CHAMA A FUNCAO processarArquivo
        fim_opcao2_label:

        fechar_arquivos:

        ; FECHA ARQUIVO DE ENTRADA
        invoke CloseHandle, handleEntradaArquivo

        ; FECHA ARQUIVO DE SAIDA 
        invoke CloseHandle, handleSaidaArquivo

    fim_operacao_arquivos:

    jmp start

    encerrarPrograma:
        invoke WriteConsole, handleSaidaConsole, addr promptEncerrar, sizeof promptEncerrar - 1, addr bytesLidos, NULL
        push 0
        call ExitProcess 

end start