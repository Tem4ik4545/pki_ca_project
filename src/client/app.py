from ui import build_ui


def main():
    demo = build_ui()
    demo.launch(server_name="109.229.236.220", server_port=7860)

if __name__ == "__main__":
    main()
