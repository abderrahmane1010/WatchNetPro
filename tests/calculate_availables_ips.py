import ipaddress
import subprocess

# Fonction pour calculer le nombre d'adresses IP disponibles dans un sous-réseau
def calculate_available_ips(subnet):
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        num_ips = sum(1 for _ in net.hosts())
        return num_ips
    except ValueError as e:
        return str(e)

# Fonction pour effectuer un ping vers une adresse IP
def ping_ip(ip):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1)
        if result.returncode == 0:
            return True
        else:
            return False
    except subprocess.TimeoutExpired:
        return False

def main():
    subnet = input("Entrez le sous-réseau (par exemple, 192.168.1.0/24) : ")

    # Calcul du nombre d'adresses IP disponibles
    num_ips = calculate_available_ips(subnet)
    if isinstance(num_ips, int):
        print(f"Nombre d'adresses IP disponibles dans le sous-réseau : {num_ips}")

        # Vérification du nombre d'adresses IP actives
        active_ips = 0
        for ip in ipaddress.IPv4Network(subnet, strict=False).hosts():
            ip = str(ip)
            if ping_ip(ip):
                active_ips += 1

        print(f"Nombre d'adresses IP actives dans le sous-réseau : {active_ips}")
    else:
        print(f"Erreur : {num_ips}")

if __name__ == "__main__":
    main()
