Алгоритм SRP6a. За основу была взята статья с Хабра: https://habr.com/ru/post/121021/
Ход работы:
1.С помощью OpenSSL генерируется большое простое число N, параметр g равен 2 (генерится ключ Диффи-Хеллмана длиной 1024 по модулю 2).
Параметр k = H(N, g), ввиду версии протокола 6а. В качестве Н используется SHA-256.
2.Создается объект класса Сервер, в его конструктор передаются N, g и k.
3.Пользовательский интерфейс: регистрация: пользователь вводит логин (I) и пароль (p), которые передаются в новый
объект класса Client вместе с N, g и k.
Client генерирует s -Соль, случайная строка), x - закрытый ключ, v - верификатор пароля и отсылает I, s, v
классу Server.
4.Аутентификация. Client вводит логин (I) и пароль (p), который передаются в новый объект класса Client вместе с N, g и k.
5.Client создаёт a - случайное число, с помощью которого он сгенерирует публичный ключ А.
6.Client отправляет I и A Server. Server проводит проверку – если A не равно нулю, то он сохраняет его себе, иначе соединение прерывается.
7.Server генерирует b - случайное число, с помощью которого он сгенерирует B - публичный ключ.
8.Server отсылает клиенту s и B. Client проводит проверку: если B равно нулю, то соединение прерывается.
9.Client и Server вычисляют скремблер u. Если u равен нулю, то соединение прерывается.
10.Client вычисляет свой закрытый ключ, общий ключ сессии S и его хэш K.
11.Server вычисляет общий ключ сессии S и его хэш K.
12.Проверка на совпадение ключей: сначала клиент вычисляет свое подтверждение M и отсылает его серверу.
Сервер вычисляет свое подтверждение M и сравнивает его с клиентским M. Если они равны, то сервер вычисляет хэш R и отсылает его клиенту.
13.Клиент вычисляет свой хэш R и сравнивает его с серверным R: при совпадении соединение устанавливается.
