from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import platform
import subprocess


def clear_terminal():
    if platform.system() == 'Windows':
        subprocess.call('cls', shell=True)
    else:
        subprocess.call('clear', shell=True)

def SPF():
    spf = str("v=spf1 ")
    end = str("-all")
    IPorDOM = str(input("Que Voulez vous rajouter à votre spf ?\n\t1 - Un domaine\n\t2 - Une IP\n"))
    if IPorDOM == "1":
        NumDom = int(input("Combien de domaine voulez-vous ajouter dans votre champ spf?\n"))
        a = 0
        while a != NumDom:
            Dom = str(input("Domaine: "))
            include = "include:"
            spf += str(include + Dom + " ")
            a += 1

    elif IPorDOM == "2":
        fourorsix = str(input("Quelle type d'adresse voulez-vous ajouter ?\n\t1 - IPv4\n\t2 - IPv6 (par défaut)\n"))
        typeIP = "0"
        if fourorsix == "1":
            typeIP = "ipv4:"
        else:
            typeIP = "ipv6:"

        NumIP = int(input("Combien d'adresse voulez-vous ajouter dans votre champ spf?\n"))
        a = 0
        while a != NumIP:
            IP = str(input("IP: "))
            spf += str(typeIP + IP + " ")
            a += 1

    else:
        print("Que 2 choix disponible ...")

    print(spf + end)
    again()

def DKIM():
    domain = str(input("Quel est votre domaine ?\n"))
    selector = str(input("Quel est le nom de votre selecteur ?\n<selecteur>._domainkey." + domain + "\n"))
    dnsregister = str(selector + "._domainkey." + domain)
    dkim = str("v=DKIM1; k=rsa; p=")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    passwKeyStr = str(input("Entrez le mot de passe pour votre clef privée\n"))
    passwKey = bytes(passwKeyStr, 'utf-8')
    private_key_pass = passwKey

    encrypted_pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
    )

    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_string = pem_public_key.decode('utf-8')

    public_key_string = public_key_string.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----','').strip()
    public_key2 = public_key_string.replace('\n','')
    public_key = public_key2.replace('= ','=')

    private_key_file = open("example-rsa.pem", "w")
    private_key_file.write(encrypted_pem_private_key.decode())
    private_key_file.close()

    public_key_file = open("example-rsa.pub", "w")
    public_key_file.write(pem_public_key.decode())
    public_key_file.close()

    val = (dkim + public_key)
    val.replace('= ','=')

    clear_terminal()
    print("Sous-domaine > " + dnsregister + "\n")
    print("Valeur > " + val + "\n")
    again()

def DMARC():
    domain = str(input("Quel est votre domaine ?\n"))
    subdomain = str("Sous domaine : _dmarc." + domain)
    dmarc = str("v=DMARC1; ")
    pol = str("p=")
    polSecure = str(input("Quelle type de politique de sécurité voulez-vous utiliser ?\n\t1 - none (aucune protection mais utile pour mode 'audit')\n\t2 - quarantine (met les e-mails non authentifiés en spam)\n\t3 - reject (mode le plus strict il rejette les e-mails non authentifié)\n"))
    if polSecure == "1":
        polSecure = str("none; ")
    elif polSecure == "2":
        polSecure = str("quarantine; ")
    elif polSecure == "3":
        polSecure = str("reject; ")
    else:
        print("Seulement 2 choix sont disponible.")
    pol = pol + polSecure

    mail = str("rua=mailto:")
    mailInput = str(input("Entrez l'adresse mail pour les rapports du DMARC : "))
    mail = str(mail + mailInput + "; ")

    pct = str("pct=100; ")
    adkim = str("adkim=s; ")
    aspf = str("aspf=s")

    print(subdomain + "\n")
    print(dmarc + pol + mail + pct + adkim + aspf)
    again()

def main():
    clear_terminal()
    Choix = str(input("Que voulez-vous faire ?\n\t1 - SPF\n\t2 - DKIM\n\t3 - DMARC\n"))
    if Choix == "1":
        SPF()
    elif Choix == "2":
        DKIM()
    elif Choix == "3":
        DMARC()
    else:
        print("Que 3 choix de disponible")

def again():
    again = str(input("Voulez-vous générer autre chose ?\n\t1 - Oui\n\t2 - Non\n"))
    if again == "1":
        again = True
    else:
        quit()

    while again == True:
        main()

main()