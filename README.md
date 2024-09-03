# Snort-Challenge---The-Basics

Witam, mamy całkiem ciekawy pokój, mam nadzieje, że nie polegnę bo jak wspominałem w podstawch snort no jestem średni z narzędzi związanych z blue team, ale czego się nie robi aby być wyżej w rankingu :P

1.Pisanie reguł IDS (HTTP)

Task 1:Użyj podanego pliku pcap.
Napisz pojedynczą regułę wykrywającą pakiety „ cały  ruch TCP  na porcie 80 ” w podanym pliku pcap. 
Jaka jest liczba wykrytych pakietów?

Zrobiłem to w nastepujacy sposób czyli: ```sudo snort mx-3.pcap 'tcp port 80'``` i otrzymaliśmy wynik 164.

Task 2: Jaki jest adres docelowy pakietu 63?

W tym przypadku trochę zmodyfikowałem polecenie z poprzedniego zadania ```sudo snort mx-3.pcap 'tcp port 80 -n 63``` - odpowiedźią na te pytanie jest 216.239.59.99

Task 3: Jaki jest  numer ACK pakietu 64?
Ponownie podmienilem z poprzedniego zadnia -n 63 na 64 i odpowiedźią jest: 0x2E6B5384

Task 4:Jaki jest  numer SEQ pakietu 62?
Podmieniamy -n 64 na -n 62 i odpowiedźią jest: 0x36C21E28

Task 5:Jaki jest  czas życia pakietu 65?
Ponownie to samo :D, znajdziemy w tym pakcie TTL - który wynosi 128

Task 6:Jaki jest źródłowy adres IP pakietu 65?
Akuratnie tu nic już nie musimy podmianić, odpowiedźią jest 145.254.160.237

![image](https://github.com/user-attachments/assets/9844c82f-3000-4d48-9226-852634630e34)

Task 7:Jaki jest port źródłowy pakietu  65?
Możemy podejrzeć na zrzucie ekranu, że port żródłowy pakietu 65 to - 3372

2.Pisanie reguł IDS (FTP)

Task 1:Napisz pojedynczą regułę wykrywającą „ cały ruch na porcie TCP 21 ” w danym pcap.
Jaka jest liczba wykrytych pakietów?

W tym przypadku nie pisałem żadnej reguły użyłem po prostu polecenia ```snort -r ftp-png-gif.pcap 'tcp port 21'```, który dał nam odpowiedź na pytanie czyli: 307

Task 2:Jaka jest nazwa usługi FTP?

W tym przypadku użyłem polecania: ```cat ftp-png-gif.pcap | grep -a "FTP"``` wynik możesz zobaczyć poniżej to też jest nasza odpowiedź
W poleceniu grep, opcja -a (lub --text) powoduje, że pliki binarne są traktowane jako tekstowe

![image](https://github.com/user-attachments/assets/ac8c8cbe-d407-4adf-9eca-80f160c3b8d1)

Task 3:Jaka jest liczba wykrytych pakietów?
W tym przypadku musieliśmy już napisać skrypt

```alert tcp any any <> any 21 (msg: "Failed"; content:"530"; sid:1000001; rev:1;)``` wygląda on bardzo podobnie co wszystkie tylko pojawiło się słowo content: 
content:"530 ": Szuka ciągu "530 " w danych, co odpowiada odpowiedzi serwera FTP oznaczającej nieudane logowanie.

Użyłem takiego polecenia do dało nam wynik: ```sudo snort -c local.rules -r snort.log.1725374915``` 

![image](https://github.com/user-attachments/assets/536ac706-79d5-4794-8bfe-1b6589b23bc6)

Task 4:Napisz regułę wykrywającą udane logowania FTP w danym pcap.
Tak naprawdę wystarczy podmienić w content:"530" na "230" i otrzymamy 1

Task 5:Napisz regułę wykrywającą  próby logowania FTP  przy użyciu prawidłowej nazwy użytkownika,  ale bez wprowadzonego hasła.
Tutaj ponownie wystarczy podmienić content, na content:"331" i otrzymamy odpowiedź 42

![image](https://github.com/user-attachments/assets/15637a51-d378-48a8-aa36-50e7359879aa)

Task 6:Napisz regułę wykrywającą  próby logowania FTP  przy użyciu nazwy użytkownika „Administrator”, ale bez podania hasła.

Troszkę zmodyfikowaliśmy nasz skrypt dodając kolejny content
alert tcp any any <> any 21 (msg: "Success"; content:"331"; content:"Administrator"; sid:1000001; rev:1;)

Wynik:

![image](https://github.com/user-attachments/assets/aeb899b6-3678-4edb-b3ed-33b7a2e1f55f)

3.Pisanie reguł IDS (PNG)
Task 1:Napisz regułę wykrywającą plik PNG w podanym pcap.
Zbadaj logi i zidentyfikuj nazwę oprogramowania osadzonego w pakiecie.
