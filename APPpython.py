import os
import json
import sys
import hashlib
import secrets
import getpass


# Função para verificar se um número é primo usando o teste probabilístico de Miller-Rabin
def is_prime(n, k=10):  # k indica o número de iterações do teste para maior precisão
    # Casos iniciais: números <= 1 não são primos
    if n <= 1:
        return False
    # 2 e 3 são primos
    if n <= 3:
        return True
    # Números pares maiores que 2 não são primos
    if n % 2 == 0:
        return False

    # Fatoração de n-1 em d * 2^r
    r, d = 0, n - 1
    # Divide d por 2 até que d seja ímpar, e conta quantas vezes isso é feito (incrementando r)
    while d % 2 == 0:
        r += 1
        d //= 2

    # Loop para realizar o teste de Miller-Rabin k vezes
    for _ in range(k):
        # Gera um número aleatório a entre 2 e n - 2
        a = secrets.randbelow(n - 3) + 2
        # Calcula x = a^d % n
        x = pow(a, d, n)

        # Se x é 1 ou n - 1, n passa no teste para esta iteração
        if x == 1 or x == n - 1:
            continue

        # Caso contrário, eleva x ao quadrado r - 1 vezes e verifica se algum valor é n - 1
        for _ in range(r - 1):
            x = pow(x, 2, n)
            # Se x se torna n - 1, n passa no teste para esta iteração
            if x == n - 1:
                break
        else:
            # Se nenhum quadrado é n - 1, n é composto
            return False
    # Se todas as iterações forem bem-sucedidas, n é considerado primo
    return True

# Função para gerar um número primo com uma quantidade específica de bits
def generate_prime(bits=512):
    while True:
        # Gera um número ímpar aleatório com o número de bits especificado
        prime_candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        # Verifica se o número gerado é primo
        if is_prime(prime_candidate):
            return prime_candidate

# Função para calcular o Máximo Divisor Comum (MDC) usando o Algoritmo de Euclides
def mdc(a, b):
    # Itera até que b seja 0
    while b != 0:
        # Atualiza a e b, onde b se torna o resto da divisão de a por b
        a, b = b, a % b
    # Retorna o valor final de a, que é o MDC
    return a

# Função para gerar o valor de e que seja coprimo ao totiente de n, o phi_n
def generate_E(phi_n):
    # Usa 65537 como valor padrão de e (primo pequeno comumente usado)
    e = 65537
    # Verifica se 65537 é coprimo com phi_n
    if mdc(phi_n, e) == 1:
        return e

    # Se 65537 não for coprimo a phi_n, itera por outros números ímpares para encontrar um coprimo
    for candidate in range(3, phi_n, 2):
        if mdc(phi_n, candidate) == 1:
            return candidate
    # Erro




    raise ValueError("Não foi possível encontrar um e coprimo ao totiente.")

# Função para calcular a chave privada d usando o Algoritmo Estendido de Euclides
def calculate_private_key(phi_n, e):
    # Variáveis para o cálculo estendido
    t, new_t = 0, 1
    r, new_r = phi_n, e
    # Executa o algoritmo de Euclides estendido
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    # Retorna t positivo
    return t + phi_n if t < 0 else t

# Função para adicionar padding PKCS#1 v1.5 à mensagem
def add_padding(message, block_size):
    # Converte a mensagem em bytes
    message_bytes = message.encode('utf-8')
    # Calcula o espaço restante no bloco (padding necessário)
    padding_length = block_size - len(message_bytes) - 3
    # Checa se a mensagem é muito longa para o bloco
    if padding_length < 0:
        raise ValueError("Mensagem muito longa para o tamanho do bloco.")

    # Gera padding PKCS#1 v1.5: começa com 0x00 e 0x02, seguido por bytes aleatórios
    padding = bytearray([0x00, 0x02]) + bytearray(secrets.randbelow(255) + 1 for _ in range(padding_length)) + bytearray([0x00]) + message_bytes
    return padding

# Função para remover padding PKCS#1 v1.5
def remove_padding(padded_message):
    # Encontra o índice do primeiro byte 0x00 após o padding
    separator_index = padded_message.find(b'\x00', 2)
    # Valida o formato do padding
    if separator_index == -1:
        raise ValueError("Formato de padding inválido.")
    # Retorna a mensagem sem o padding
    return padded_message[separator_index + 1:].decode('utf-8')

# Função para cifrar uma mensagem usando a chave pública (e, n)
def cipher(message, e, n):
    # Calcula o tamanho do bloco baseado no tamanho de n
    block_size = (n.bit_length() + 7) // 8
    # Adiciona padding à mensagem
    padded_message = add_padding(message, block_size)
    # Converte a mensagem com padding para inteiro
    int_message = int.from_bytes(padded_message, 'big')
    # Cifra a mensagem com a fórmula: int_message^e % n
    return pow(int_message, e, n)

# Função para decifrar uma mensagem usando a chave privada d
def descifra(cifra, n, d):
    # Descriptografa a mensagem cifrada com: cifra^d % n
    int_message = pow(cifra, d, n)
    # Converte o número inteiro decifrado em bytes
    padded_message = int_message.to_bytes((int_message.bit_length() + 7) // 8, 'big')
    # Remove o padding e retorna a mensagem original
    return remove_padding(padded_message)

# Função para gerar chaves pública e privada RSA
def generate_keys(bits=128):
    # Gera dois números primos grandes
    p = generate_prime(bits)
    q = generate_prime(bits)
    # Calcula n como produto de p e q
    n = p * q
    # Calcula o totiente de n (phi_n)
    totient_de_N = (p - 1) * (q - 1)
    # Gera o valor de e coprimo a phi_n
    e = generate_E(totient_de_N)
    # Calcula a chave privada d
    d = calculate_private_key(totient_de_N, e)
    # Remove p, q e totient para segurança
    del p, q, totient_de_N
    # Retorna a chave pública (n, e) e a chave privada d
    return (n, e), d

# Função para salvar a chave privada em um arquivo
def save_private_key(username, private_key):
    # Salva a chave privada em um arquivo chamado 'private_key.txt'
    with open('private_key.txt', 'w') as f:
        f.write(str(username))
        f.write(str(private_key))

def save_public_key(username, public_key):
  with open('public_key.txt', 'w') as f:
        f.write(str(username))
        f.write(str(public_key))



# Função para salvar a mensagem cifrada em um arquivo
def save_encrypted_message(username, encrypted_message):
    # Salva a mensagem cifrada em um arquivo chamado 'encrypted_message.txt'
    with open('encrypted_message.txt', 'w') as f:
        f.write(str(encrypted_message))
        f.write(str(encrypted_message))

# Função para criar um hash SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Função para carregar usuários do arquivo
def load_users():
    if os.path.exists('users.json'):
        with open('users.json', 'r') as f:
            return json.load(f)
    return {}

# Função para salvar usuários no arquivo
def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(users, f)

# Função para verificar se o usuário é admin
def eh_almir(username):
    users = load_users()
    return users.get(username, {}).get("permissão") == "almirante"

# Função para registrar um novo usuário com um nível de permissão
def register_user(username, password, permission_level):
    users = load_users()
    if username in users:
        print("Usuário já existe. Tente outro nome.")
        return False
    users[username] = {

        "senha": hash_password(password),
        "permissão": permission_level
    }
    save_users(users)
    print("Usuário registrado com sucesso!")
    return True

# Função para fazer login e retornar o nível de permissão do usuário
def login_user(username, password):
    users = load_users()
    if username not in users:
        print("Usuário não encontrado.")
        return None
    if users[username]["senha"] == hash_password(password):
        print("Login bem-sucedido!")
        return users[username]["permissão"]
    else:
        print("Senha incorreta.")
        return None

# Função para deletar um usuário, somente permitido a admins
def delete_user(username):
    users = load_users()
    if username in users:
        del users[username]
        save_users(users)
        print(f"Usuário '{username}' deletado com sucesso.")
        return True
    else:
        print("Usuário não encontrado.")
        return False



def enviaMensagem(username):


    # Solicita a mensagem do usuário
    text = input("Digite: ")
    # Gera as chaves pública e privada com 512 bits
    public_key, private_key = generate_keys(128)
    # Extrai n e e da chave pública
    n, e = public_key
    # Exibe a chave pública e privada
    print(f"{username}, sua chave privada é: ", private_key)
    print(f"{username}, sua chave publica é: ", public_key)
    # Cifra a mensagem e exibe o resultado
    text_cipher = cipher(text, e, n)
    print('Sua mensagem cifrada:', text_cipher)
    # Salva a chave privada em um arquivo
    save_private_key(username, private_key)
    # Salva a mensagem cifrada em um arquivo
    save_encrypted_message(username,
                           text_cipher)
    # Salva a chave publica em um arquivo
    save_public_key(username, public_key)
    # Exibe a chave privada

    # Descriptografa a mensagem e exibe o texto original
    original_text = descifra(text_cipher, n, private_key)
# Função principal do programa
def main():


    while True:
        print("                ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~")
        print("                      |\\")
        print("                  /^^\\")
        print("                 |        |")
        print("                 ||")
        print("          /\\/          \\/\\")
        print("        |---------MARINHA----------|")
        print("         \\o o o o o o o o o o o o/")




        print("\nEscolha uma opção:")
        print("1. Registrar")
        print("2. Login")
        print("3. Deletar Usuário")
        print("4. Sair")
        choice = input("Opção: ")

        if choice == '1':
            username = input("Nome de usuário: ")
            password = input("Senha: ")
            permission = input("Nível de permissão ('almirante' ou 'marinheiro'): ")
            if permission not in ["almirante", "marinheiro"]:
                print("Permissão inválida. Escolha entre 'admin' e 'user'.")
            else:
                register_user(username, password, permission)

        elif choice == '2':
            username = input("Nome de usuário: ")
            password = getpass.getpass("Senha: ")
            permission_level = login_user(username, password)
            if permission_level:
                print(f"Bem-vindo, {username}. Você tem permissão '{permission_level}'.")

                # Menu após o login
                while True:
                    print("\nEscolha uma opção:")
                    print("1. Realizar uma ação")
                    if eh_almir(username):  # Verifica se o usuário é admin
                        print("2. Deletar outro usuário")
                        print("3. Descriptografar mensagem")
                        print("4. Enviar Mensagem: ")
                    print("5. Logout")
                    sub_choice = input("Opção: ")

                    if sub_choice == '1':
                        print("Ação realizada com sucesso!")
                    elif sub_choice == '2' and eh_almir(username):
                        delete_username = input("Nome de usuário para deletar: ")
                        confirm = input("Tem certeza que deseja deletar esse usuário? (s/n): ").lower()
                        if confirm == 's':
                            delete_user(delete_username)
                    elif sub_choice == '3' and eh_almir(username):
                        temmensagem = input("Você tem uma mensagem para descriptografar? (S/N): ")
                        if temmensagem == "S" or temmensagem == "s":
                          encrypted_message = int(input("Insira a mensagem cifrada (como número inteiro): "))
                          n = int(input("Insira a chave pública: "))
                          private_key = int(input("Insira a chave privada: "))
                          try:
                            original_message = descifra(encrypted_message, n, private_key)
                            print(f"A mensagem original é: {original_message}")
                          except Exception as e:
                            print(f"Falha na descriptografia. Mensagem inexistente ou incorreta.")
                        else:
                          print("Sem mensagems. Retornando...")
                          continue



                    elif sub_choice == '4' and eh_almir(username):
                      print("Para qual navio deseja enviar a mensagem?")
                      print("")
                      print("")
                      print("1. A140 – Atlântico")
                      print("2. F41 – Defensora")
                      print("3. F42 – Constituição")
                      print("4. Navio Tanque: G23 – “Almirante Gastão Motta”")

                      escolhanavio = int(input("Navio n°: "))
                      #
                      if escolhanavio == 1:
                        print(f"Enviando mensagem ao navio {escolhanavio} A140 – Atlântico:")
                        enviaMensagem(username)

                      elif escolhanavio == 2:
                        print(f"Enviando mensagem ao navio {escolhanavio} F41 – Defensora:")
                        enviaMensagem(username)

                      elif escolhanavio == 3:
                        print(f"Enviando mensagem ao navio {escolhanavio} F42 – Constituição:")
                        enviaMensagem(username)

                      elif escolhanavio == 4:
                        print(f"Enviando mensagem ao navio {escolhanavio} A140 – Navio Tanque: G23 – “Almirante Gastão Motta”:")
                        enviaMensagem(username)


                    elif sub_choice == '5':
                        print("Saindo...")
                        break
                    else:
                        print("Opção inválida ou permissão insuficiente.")
            else:
                print("Falha na autenticação.")

        elif choice == '3':
            print("Para deletar um usuário, faça login como admin.")
        elif choice == '4':
            print("Saindo...")
            break
        else:
            print("Opção inválida. Tente novamente.")

if _name_ == '_main_':
    main()