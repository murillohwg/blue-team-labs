from urllib.parse import unquote

while True:
    uri = input("Cole a URI: ")

    try:
        print("\n===== DECODED =====\n")
        print(unquote(uri))
        print("\n===================\n")
    except Exception as e:
        print(f"Erro: {e}")
