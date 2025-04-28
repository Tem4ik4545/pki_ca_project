# src/client/ui.py

import requests
import gradio as gr
from utils import generate_csr_and_issue, revoke_cert, get_crl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from utils import check_ocsp_status
def build_ui() -> gr.Blocks:
    demo = gr.Blocks(title="Тонкий клиент PKI УЦ")

    with demo:
        # Заголовки
        gr.Markdown("# Тонкий клиент Удостоверяющего Центра")
        gr.Markdown("Заполните поля и нажмите «Выпустить» — автоматически получите ключ и сертификат.")

        # 1. Выпуск X.509
        with gr.Tab("Выпуск X.509"):
            gr.Markdown("**Заполните все поля и нажмите «Выпустить»**")
            cn      = gr.Textbox(label="CN (Общее имя)")
            org     = gr.Textbox(label="Организация (O)")
            ou      = gr.Textbox(label="Подразделение (OU)")
            loc     = gr.Textbox(label="Город (L)")
            state   = gr.Textbox(label="Штат/Область (ST)")
            country = gr.Textbox(label="Страна (C)")
            email   = gr.Textbox(label="Email")
            issue_btn   = gr.Button("Выпустить")
            key_file    = gr.File(label="Приватный ключ (PEM)")
            cert_file   = gr.File(label="Сертификат (PEM)")
            status_text = gr.Textbox(label="Статус", lines=2)
            serial_text = gr.Textbox(label="Серийный номер", lines=1)

            def safe_issue(cn, org, ou, loc, state, country, email):
                # Проверка на пустые поля
                missing = [
                    name for name, val in [
                        ("CN", cn), ("O", org), ("OU", ou),
                        ("L", loc), ("ST", state),
                        ("C", country), ("Email", email)
                    ] if not val or not str(val).strip()
                ]
                if missing:
                    return None, None, f"Заполните поля: {', '.join(missing)}", ""

                try:
                    # Выпускаем и сохраняем пути к файлам
                    key_path, cert_path = generate_csr_and_issue(
                        cn, org, ou, loc, state, country, email
                    )

                    # Загружаем PEM-сертификат и извлекаем serial
                    pem = open(cert_path, "rb").read()
                    cert_obj = x509.load_pem_x509_certificate(pem, default_backend())
                    serial = cert_obj.serial_number

                    return key_path, cert_path, "✔ Выпуск успешен", str(serial)

                except requests.HTTPError as he:
                    try:
                        detail = he.response.json().get("detail", he.response.text)
                    except Exception:
                        detail = he.response.text
                    return None, None, f"Ошибка сервера: {detail}", ""
                except Exception as e:
                    return None, None, f"Непредвиденная ошибка: {e}", ""

            issue_btn.click(
                fn=safe_issue,
                inputs=[cn, org, ou, loc, state, country, email],
                outputs=[key_file, cert_file, status_text, serial_text]
            )

        # 2. Отзыв сертификата
        with gr.Tab("Отзыв сертификата"):
            gr.Markdown("**Введите серийный номер и причину, затем нажмите «Отозвать»**")
            # Текстовое поле вместо Number, чтобы не терять точность длинного серийника
            sn = gr.Textbox(
                label="Серийный номер (десятичный)",
                placeholder="Скопируйте из поля «Serial Number» вкладки «Выпуск X.509»"
            )
            reason = gr.Textbox(label="Причина отзыва")
            revoke_btn = gr.Button("Отозвать")
            revoke_output = gr.Textbox(label="Результат", lines=4)

            def do_revoke(serial_str, reason):
                serial_str = str(serial_str).strip()
                # Проверяем, что строка состоит только из цифр
                if not serial_str.isdigit():
                    return "❌ Формат серийного номера неверен: допускаются только цифры."
                serial = int(serial_str)
                try:
                    r = revoke_cert(serial, reason)
                    return (
                        f"✔ Сертификат отозван:\n"
                        f"- Серийный номер: {r['serial_number']}\n"
                        f"- Дата: {r['revocation_date']}\n"
                        f"- Причина: {r['reason']}"
                    )
                except requests.HTTPError as he:
                    # Пытаемся достать сообщение detail из JSON
                    try:
                        detail = he.response.json().get("detail", he.response.text)
                    except Exception:
                        detail = he.response.text
                    return f"❌ Ошибка сервера: {detail}"
                except Exception as e:
                    return f"❌ Непредвиденная ошибка: {e}"

            revoke_btn.click(
                fn=do_revoke,
                inputs=[sn, reason],
                outputs=revoke_output
            )

        # 3. Получить CRL
        with gr.Tab("Получить CRL"):
            gr.Markdown("**Нажмите «Загрузить отзывы» для получения списка отозванных сертификатов**")
            load_btn = gr.Button("Загрузить отзывы")
            crl_table = gr.Dataframe(
                headers=["serial_number", "revocation_date", "reason"],
                datatype=["str", "str", "str"],
                row_count=(0, None),
                col_count=3,
                interactive=False,
                label="Список отзывов"
            )

            def fetch_crl_list():
                """
                Вызывает API /crl и преобразует ответ List[dict] в формат List[List],
                пригодный для отображения в gr.Dataframe:
                    [
                        [serial_number, revocation_date, reason],
                        …
                    ]
                """
                data = get_crl() or []
                table = []
                for entry in data:
                    serial = entry.get("serial_number", "")
                    date = entry.get("revocation_date", "")
                    reason = entry.get("reason", "")
                    table.append([serial, date, reason])
                return table

            load_btn.click(
                fn=fetch_crl_list,
                inputs=None,
                outputs=crl_table
            )

        # 4. OCSP-резондер
        with gr.Tab("OCSP-проверка"):
            gr.Markdown("**Проверить статус сертификата через OCSP**\n\n"
                        "Загрузите оба PEM-файла: ваш сертификат и сертификат CA-издателя.")
            user_cert   = gr.File(label="Ваш сертификат (PEM)", file_types=[".pem"])
            issuer_cert = gr.File(label="Сертификат издателя (PEM)", file_types=[".pem"])
            btn         = gr.Button("Проверить статус")
            out_text    = gr.Textbox(label="Результат OCSP-запроса", lines=6)

            def do_ocsp(user_file, issuer_file):
                try:
                    # читаем байты
                    user_pem   = user_file.read()   if hasattr(user_file, "read")   else open(user_file, "rb").read()
                    issuer_pem = issuer_file.read() if hasattr(issuer_file, "read") else open(issuer_file, "rb").read()

                    res = check_ocsp_status(user_pem, issuer_pem)

                    lines = [
                        f"Статус: {res['status']}",
                        f"Последнее обновление: {res['this_update']}",
                        f"Следующая проверка: {res['next_update']}"
                    ]
                    if res["status"] == "REVOKED":
                        lines += [
                            f"Отозвано: {res['revocation_time']}",
                            f"Причина: {res['revocation_reason']}"
                        ]
                    return "\n".join(lines)
                except Exception as e:
                    return f"Ошибка OCSP-проверки: {e}"

            btn.click(
                fn=do_ocsp,
                inputs=[user_cert, issuer_cert],
                outputs=out_text
            )

        # 5. Руководство
        with gr.Tab("Руководство"):
            gr.Markdown("""
**1. Выпуск X.509**  
Заполните поля и нажмите **«Выпустить»**.  
Если какие-то поля не заполнены — вы увидите подсказку.

**2. Отзыв сертификата**  
Введите серийный номер (скопируйте из поля «Serial Number» вкладки «Выпуск X.509») и причину, нажмите **«Отозвать»**.

**3. CRL**  
Нажмите **«Загрузить CRL»** — получите список отозванных сертификатов.

**4. OCSP**  
Загрузите файл запроса DER, нажмите **«Отправить запрос»** — скачайте ответ DER.
            """)

    return demo
