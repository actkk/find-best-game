import base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from scapy.all import *


def parse_pkts(pcap_file: str) -> bytes:
    """
    Parses TLS packets from a PCAP file and extracts the encrypted premaster secret (if found).

    Args:
        pcap_file: Path to the PCAP file containing TLS handshake packets.

    Returns:
        The encrypted premaster secret (if found), otherwise None.
    """

    load_layer("tls")
    packets = rdpcap(pcap_file)

    premaster_secret = None
    for pkt in packets[TLS]:
        if pkt.haslayer(TLSClientHello) and "random_bytes" in pkt.show(dump=True):
            client_random = pkt[TLSClientHello].random_bytes
        elif pkt.haslayer(TLSServerHello) and "random_bytes" in pkt.show(dump=True):
            server_random = pkt[TLSServerHello].random_bytes
        elif pkt.haslayer(TLSClientKeyExchange):
            premaster_secret = pkt[TLSClientKeyExchange].encrypted_premaster_secret

    return premaster_secret


def decrypt_premaster(premaster_secret: bytes, server_key_path: str) -> bytes:
    """
    Decrypts the premaster secret using the server's RSA private key.

    Args:
        premaster_secret: The encrypted premaster secret.
        server_key_path: Path to the file containing the server's RSA private key.

    Returns:
        The decrypted premaster secret.
    """

    with open(server_key_path, "rb") as f:
        server_key = RSA.import_key(f.read())
    cipher = PKCS1_v1_5.new(server_key)
    return cipher.decrypt(premaster_secret, "")


def decrypt_data(app_data: list, master_secret: bytes) -> None:
    """
    Attempts to decrypt a list of application data using the derived master secret.

    Args:
        app_data: A list of byte strings representing application data packets.
        master_secret: The TLS master secret derived from the handshake.

    Prints the decrypted data if successful, otherwise handles decryption failures.
    """

    # Derive key material using a PRF (implementation omitted for brevity)
    derived_keys = prf.derive_key_block(master_secret, req_len=32)  # Replace with actual implementation

    cipher = AES.new(derived_keys[:16], AES.MODE_CBC)  # Use first 16 bytes for key

    decrypted_data = b""
    for data in app_data:
        decrypted_data += cipher.decrypt(data)

    try:
        print(decrypted_data.decode("utf-8"))  # Assuming data is UTF-8 encoded
    except UnicodeDecodeError:
        print("Failed to decode decrypted data (may not be UTF-8).")


def main():
    """
    Main function to parse packets, decrypt premaster secret, derive keys, and attempt decryption.
    """

    load_layer("tls")
    pcap_file = "best_game.pcap"  # Replace with actual file path
    server_key_path = "server.key"  # Replace with actual key file path

    premaster_secret = parse_pkts(pcap_file)
    if premaster_secret is None:
        print("Encrypted premaster secret not found in the PCAP file.")
        return

    decrypted_premaster = decrypt_premaster(premaster_secret, server_key_path)

    # Reconstruct TLS session and derive master secret (implementation omitted for brevity)
    master_secret = compute_master_secret(decrypted_premaster, client_random, server_random)

    # Extract application data from packets (implementation omitted for brevity)
    application_data = extract_application_data(packets)

    decrypt_data(application_data, master_secret)


if __name__ == "__main__":
    main()
