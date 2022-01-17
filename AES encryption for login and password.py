from random import randint
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

class Create:
  def __init__(self, login, password, key):
           self.login = login ; self.password = password ; self.key = key

  def setAccount(self):                              #Ввод логина ,пароля + проверка пароля.
     while True:
         self.login = input('Введите логин: ').replace(" ", "")
         if len(self.login) < 6:
              print('Логин слишком короткий. Логин должен состоять больше чем из 6 символов!')
         else:
              break
     while True:
         self.password = input('Введите пароль. Пароль должен сожержать не менее 6 символов. Прописные и заглавные буквы, а так же иметь числа: ').replace(" ", "")
         if len(self.password) >=6 and any(map(str.isdigit, self.password)) == True and any(map(str.isupper, self.password)) == True and any(map(str.islower, self.password)) == True:
             break
         else:
             print('Пароль введен некорректно')
     while True:
         lenkey = input('Введите длину ключа')
         if lenkey.isdigit():
              lenkey = int(lenkey)
              break
         else:
              print('Некоректный ввод. Введите число')
     range_start = 10**(lenkey-1)
     range_end = (10**lenkey)-1
     self.key = randint(range_start, range_end) # генератор пароля


class Translate_AES(Create):
  @staticmethod
  def encrypt(plain_text, key):  #Функция шифрования
    salt = get_random_bytes(AES.block_size)
    private_key = hashlib.scrypt(
        key.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    cipher_config = AES.new(private_key, AES.MODE_GCM)
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }
  @staticmethod
  def decrypt(enc_dict, key):   #Функция расшифрование
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    private_key = hashlib.scrypt(
        key.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)
    return decrypted


Acc_mas = []   #Массив куда сохраняются зашифрованный логин + пароль
Key_mas = []   #Массив куда сохраняются ключи

while True:
    Move = input('Что бы создать новый аккаунт введите "1" (в документ сохраняется зашифрованный вид) \nЧто бы узнать логин и пароль под номером N введите "2" \nЧто бы выйти "3"\n')


    if Move == '1':        #Добавить аккаунт + шифрование
        Account = Create(1,2,3)
        Account.setAccount()
        Log_Pas = Account.login + ' ' + Account.password
        Acc_mas += [Translate_AES.encrypt(Log_Pas,str(Account.key))]
        Key_mas += [str(Account.key)]
        print('Аккаунт с логином "'+ Account.login + '"  успешно зашифрован.')


    elif Move == '2':     #Вывести N-ый аккаунт
        if len(Acc_mas) != 0:
            while True:
                N = input('Введите номер аккаунта который хотите расшифровать и вывести на экран. Всего сохранено: ' \
                          + str(len(Acc_mas)) + '\n Введите чило от 1 до ' + str(len(Acc_mas))+'\n')
                if N.isdigit():
                    N = int(N)
                    if N <= len(Acc_mas) and N>0:
                        log_out = Translate_AES.decrypt(Acc_mas[N-1], Key_mas[N-1]).decode('utf-8').split()
                        print('Вызываемый логин и пароль успешно расшифрован. \n Логин:  ' + log_out[0]+'\n'+'Пароль:  '+log_out[1]+'\n')
                        break
                    else:
                        print('Некоректный ввод! Значение не попадает в диапазон!')
                else:
                    print('Некоректный ввод. Введите число!')
        else:
            print('На данный момент зашифрованных аккаунтов нет.')


    elif Move == '3':     #Выход
        break

    else:
        print('Введите число для выбора действия')