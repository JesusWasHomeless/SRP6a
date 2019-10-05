import javax.naming.InvalidNameException;
import java.math.BigInteger;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        // N generated using "openssl dhparam -text 1024 -2",
        // where g equals 2
        String N_hex = "00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:" +
                "4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:" +
                "c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:" +
                "97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:" +
                "c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:" +
                "c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:" +
                "16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:" +
                "9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:" +
                "d0:d4:ca:3c:50:0b:88:5f:e3";
        BigInteger N = new BigInteger(N_hex.replace(":", ""), 16);
        BigInteger g = BigInteger.valueOf(2);
        // in SRP6a, k = H(N, g)
        BigInteger k = SHA256.hash(N, g);

        Server server = new Server(N, g, k);

        while (true) {
            System.out.println("Войти или зарегистрироваться?");
            System.out.println("1. Зарегистрироваться");
            System.out.println("2. Войти");
            Scanner input = new Scanner(System.in);
            int choice = input.nextInt();
            switch (choice) {
                // Регистрация
                case 1: {
                    System.out.println("Введите логин: ");
                    String login = input.next();

                    System.out.println("Введите пароль: ");
                    String password = input.next();

                    Client client = new Client(N, g, k, login, password);

                    client.set_SXV();
                    String s = client.get_s();
                    BigInteger v = client.get_v();
                    try {
                        server.set_ISV(login, s, v);
                        //Если в мапе есть имя, то:
                    } catch (InvalidNameException e) {
                        System.out.println("Имя занято!");
                    }
                    break;
                }
                // Вход
                case 2: {
                    System.out.println("Введите логин: ");
                    String login = input.next();

                    System.out.println("Введите пароль: ");
                    String password = input.next();

                    Client client = new Client(N, g, k, login, password);


                    BigInteger A = client.gen_A();
                    try {
                        server.set_A(A);

                    } catch (IllegalAccessException e) {
                        System.out.println("A = 0");
                        break;
                    }

                    try {
                        String s = server.get_s(login);
                        BigInteger B = server.create_B();
                        client.receiveSaltAndB(s, B);
                    } catch (IllegalAccessException e) {
                        System.out.println("Такого пользователя не существует");
                        break;
                    }

                    try {
                        client.gen_u();
                        server.gen_u();
                    } catch (IllegalAccessException e) {
                        System.out.println("Соединение прервано!");
                        break;
                    }

                    client.SessionKey();
                    server.SessionKey();

                    BigInteger server_R = server.create_M(client.ClientConfirm());

                    if (client.compare_R_C(server_R))
                        System.out.println("Соединение установлено");
                    else
                        System.out.println("Неверный пароль");
                    break;
                }
                default:
                    return;
            }
            System.out.println();
        }
    }
}