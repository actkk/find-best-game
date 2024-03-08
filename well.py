import subprocess

# Dosya yolları
pcap_file = '/home/ahmet/Projects/FindBestGame/best_game.pcap'
key_file = '/home/ahmet/Projects/FindBestGame/server.key'

# tshark komutu, belirli alanları (-e ile) çıkar
tshark_cmd = [
    'tshark', '-r', pcap_file,
    '-o', f'tls.keys_list:rsa_keys:{key_file}',
    '-Y', 'tls',
    '-T', 'fields',  # Alanları belirli formatlarda çıkarmak için
    '-e', 'frame.number',  # Çerçeve numarası
    '-e', 'tls.record.content_type',  # İçerik türü
    '-e', 'tls.app_data'  # Uygulama verisi (Not: Bu alan her zaman mevcut olmayabilir veya beklediğiniz verileri içermeyebilir)
]

try:
    # subprocess ile tshark komutunu çalıştır ve çıktıyı yakala
    result = subprocess.run(tshark_cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    else:
        print("Çıktıda ilgili TLS verisi bulunamadı.")
except Exception as e:
    print(f"Komut çalıştırılırken hata oluştu: {e}")
