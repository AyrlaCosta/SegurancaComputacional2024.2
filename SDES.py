"""
Trabalho 1 de Segurança Computacional
Aluna: Ayrla Danielly Nascimento Costa - 190025069
Universidade de Brasília
Departamento de Ciências da Computação
"""


def criptografar_SDES(plaintext, key) -> str:
    subchaves = gerar_subchave(key)

    estado = permutacao_inicial(plaintext)

    # dois rounds da rede de Feistel
    for i in range(2):
        estado = feistel(estado, subchaves[i])

    estado = estado[4:] + estado[:4]
    texto_cifrado = permutacao_final(estado)

    return texto_cifrado


def descriptografar_SDES(ciphertext, key) -> str:
    subchaves = gerar_subchave(key)

    estado = permutacao_inicial(ciphertext)

    # dois rounds da rede de Feistel
    for i in range(1, -1, -1):
        estado = feistel(estado, subchaves[i])

    plaintext = permutacao_final(estado)

    return plaintext


def gerar_subchave(key) -> list:
    # P10
    key = permutacao_10(key)

    L = key[:5]
    R = key[5:]

    L = L[1:] + L[0]
    R = R[1:] + R[0]

    subchave_1 = permutacao_8(L + R)

    L = L[1:] + L[0]
    R = R[1:] + R[0]
    L = L[1:] + L[0]
    R = R[1:] + R[0]

    subchave_2 = permutacao_8(L + R)

    subchaves = [subchave_1, subchave_2]

    return subchaves


def permutacao_inicial(plaintext) -> str:
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    textoPermutado = ""
    for i in IP:
        textoPermutado += plaintext[i-1]
    return textoPermutado


def expandir_permutacao(R0) -> str:
    E_P = [4, 1, 2, 3, 2, 3, 4, 1]
    textoPermutado = ""
    for i in E_P:
        textoPermutado += R0[i-1]
    return textoPermutado


def permutacao_10(key):
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    chavePermutada = ""
    for i in P10:
        chavePermutada += key[i-1]
    return chavePermutada


def permutacao_8(key):
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    chavePermutada = ""
    for i in P8:
        chavePermutada += key[i-1]
    return chavePermutada


def permutacao_4(R0_F) -> str:
    P4 = [2, 4, 3, 1]
    textoPermutado = ""
    for i in P4:
        textoPermutado += R0_F[i-1]
    return textoPermutado


def permutacao_final(estado) -> str:
    IP_1 = [4, 1, 3, 5, 7, 2, 8, 6]
    textoPermutado = ""
    for i in IP_1:
        textoPermutado += estado[i-1]
    return textoPermutado


def sbox_0(L) -> str:
    S0 = [['01', '00', '11', '10'], ['11', '10', '01', '00'], ['00', '10', '01', '11'], ['11', '01', '11', '10']]
    row = int(L[0] + L[-1], 2)
    column = int(L[1:3], 2)
    sboxed = S0[row][column]
    return sboxed


def sbox_1(R) -> str:
    S1 = [['00', '01', '10', '11'], ['10', '00', '01', '11'], ['11', '00', '01', '00'], ['10', '01', '00', '11']]
    row = int(R[0] + R[-1], 2)
    column = int(R[1:3], 2)
    sboxed = S1[row][column]
    return sboxed


def feistel(estado, subchave) -> str:
    L0 = estado[:4]
    R0 = estado[4:]

    R1 = pad(xor(L0, F(R0, subchave)), 4)
    L1 = R0
    estado = L1 + R1
    return estado


def F(R0, subchave) -> str:
    R0_F = expandir_permutacao(R0)

    # XOR com subchave
    R0_F = pad(xor(R0_F, subchave), 8)

    L = R0_F[:4]
    R = R0_F[4:]

    L = sbox_0(L)
    R = sbox_1(R)
    R0_F = L + R

    R0_F = permutacao_4(R0_F)
    return R0_F


def xor(a, b):
    return bin(int(a, 2) ^ int(b, 2))[2:].zfill(len(a))


def pad(a, b):
    while len(a) < b:
        a = '0' + a
    return a


# Exemplo oferecido na descrição do trabalho
textoPlano = '11010111'
chave = '1010000010'
textoCifrado = criptografar_SDES(textoPlano, chave)
descriptografado = descriptografar_SDES(textoCifrado, chave)
print(f"Bloco de dados de 8 bits = {textoPlano}\nTexto cifrado = {textoCifrado}\nTexto descriptografado = {descriptografado}")
