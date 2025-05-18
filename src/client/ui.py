# src/client/ui.py

import requests
import gradio as gr
from utils import generate_csr_and_issue, revoke_cert, get_crl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from utils import check_ocsp_status
from utils import verify_admin
from utils import do_revoke_ui, fetch_crl_ui

def build_ui() -> gr.Blocks:
    demo = gr.Blocks(title="Тонкий клиент PKI УЦ")

    with demo:
        # Заголовки
        gr.Markdown("# Клиент Удостоверяющего Центра")
        gr.Markdown("Заполните поля и нажмите «Выпустить» — автоматически получите ключ и сертификат.")

        # 1. Выпуск X.509
        with gr.Tab("Выпуск X.509"):
            gr.Markdown("**Заполните все поля и нажмите «Выпустить»**")

            # Выбор УЦ (если нужно) — иначе можно оставить пустым для автоматического выбора
            ca_name = gr.Dropdown(
                choices=["", "int1", "int2"],
                value="",
                label="Выберите УЦ (оставьте пустым — Root CA)"
            )
            cn = gr.Textbox(label="CN (Общее имя)")
            org = gr.Textbox(label="Организация (O)")
            ou = gr.Textbox(label="Подразделение (OU)")
            loc = gr.Textbox(label="Город (L)")
            state = gr.Textbox(label="Штат/Область (ST)")
            country = gr.Textbox(label="Страна (C)")
            email = gr.Textbox(label="Email")
            issue_btn = gr.Button("Выпустить")
            key_file = gr.File(label="Приватный ключ (PEM)")
            cert_file = gr.File(label="Сертификат (PEM)")
            status = gr.Textbox(label="Статус", lines=2)
            serial = gr.Textbox(label="Серийный номер", lines=1)

            def safe_issue(ca_name_value, cn, org, ou, loc, state, country, email):
                missing = [n for n, v in [
                    ("CN", cn), ("O", org), ("OU", ou),
                    ("L", loc), ("ST", state),
                    ("C", country), ("Email", email)
                ] if not (v and str(v).strip())]
                if missing:
                    return None, None, f"Заполните поля: {', '.join(missing)}", ""

                try:
                    key_path, cert_path, serial = generate_csr_and_issue(
                        cn, org, ou, loc, state, country, email, ca_name_value
                    )
                    return key_path, cert_path, "✔ Выпуск успешен", serial

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
                inputs=[ca_name, cn, org, ou, loc, state, country, email],
                outputs=[key_file, cert_file, status, serial]
            )

        with gr.Tab("Отзыв сертификата"):
            gr.Markdown("**Доступ только для администратора.**")
            admin_pwd = gr.Textbox(label="Пароль администратора", type="password")
            login_btn = gr.Button("Войти")

            # Поля для отзыва (скрываем до авторизации)
            sn = gr.Textbox(
                label="Серийный номер (десятичный)",
                placeholder="Скопируйте из вкладки «Выпуск X.509»",
                visible=False
            )
            reason = gr.Textbox(label="Причина отзыва", visible=False)
            revoke_btn = gr.Button("Отозвать", visible=False)
            # Это поле оставляем видимым (но пустым) после успешной авторизации
            revoke_out = gr.Textbox(label="Результат операции", lines=4, visible=False)

            def unlock_revoke(pwd: str):
                try:
                    ok = verify_admin(pwd)
                except Exception as e:
                    return (
                        gr.update(visible=False),  # sn
                        gr.update(visible=False),  # reason
                        gr.update(visible=False),  # revoke_btn
                        gr.update(visible=True, value=f"❌ Ошибка проверки пароля: {e}"),  # revoke_out
                        gr.update(visible=True, value=""),  # admin_pwd
                        gr.update(visible=True)  # login_btn
                    )
                if not ok:
                    return (
                        gr.update(visible=False),
                        gr.update(visible=False),
                        gr.update(visible=False),
                        gr.update(visible=True, value="❌ Неверный пароль"),
                        gr.update(visible=True, value=""),
                        gr.update(visible=True)
                    )
                # успешная авторизация:
                # показываем поля для отзыва и оставляем revoke_out видимым (пока пустым)
                return (
                    gr.update(visible=True),  # sn
                    gr.update(visible=True),  # reason
                    gr.update(visible=True),  # revoke_btn
                    gr.update(visible=True, value=""),  # revoke_out
                    gr.update(visible=False),  # admin_pwd
                    gr.update(visible=False)  # login_btn
                )

            login_btn.click(
                fn=unlock_revoke,
                inputs=admin_pwd,
                outputs=[sn, reason, revoke_btn, revoke_out, admin_pwd, login_btn]
            )

            def do_revoke_ui(serial_str: str, reason_str: str) -> str:
                serial_str = serial_str.strip()
                if not serial_str.isdigit():
                    return "❌ Формат серийного номера неверен: только цифры."
                serial = int(serial_str)
                try:
                    r = revoke_cert(serial, reason_str)
                    return (
                        f"✔ Сертификат отозван:\n"
                        f"- Серийный номер: {r['serial_number']}\n"
                        f"- Дата отзыва: {r['revocation_date']}\n"
                        f"- Причина: {r['reason']}"
                    )
                except requests.HTTPError as he:
                    try:
                        detail = he.response.json().get("detail", he.response.text)
                    except:
                        detail = he.response.text
                    return f"❌ Ошибка сервера: {detail}"
                except Exception as e:
                    return f"❌ Непредвиденная ошибка: {e}"

            revoke_btn.click(
                fn=do_revoke_ui,
                inputs=[sn, reason],
                outputs=[revoke_out]
            )

        with gr.Tab("Получить CRL"):
            gr.Markdown("**Доступ только для администратора.**")
            admin_pwd2 = gr.Textbox(label="Пароль администратора", type="password")
            login_btn2 = gr.Button("Войти")

            load_btn = gr.Button("Загрузить отзывы", visible=False)
            crl_table = gr.Dataframe(
                headers=["Серийный номер", "Дата отзыва", "Причина"],
                datatype=["str", "str", "str"],
                row_count=(0, None),
                col_count=3,
                interactive=False,
                label="Список отозванных сертификатов",
                visible=False
            )
            msg_crl = gr.Textbox(label="", visible=False)

            def unlock_crl(pwd):
                try:
                    ok = verify_admin(pwd)
                except Exception as e:
                    return (
                        gr.update(visible=False),  # load_btn
                        gr.update(visible=False),  # crl_table
                        gr.update(visible=True, value=f"❌ Ошибка проверки пароля: {e}"),  # msg_crl
                        gr.update(visible=True, value=""),  # admin_pwd2 очистить
                        gr.update(visible=True)  # login_btn2
                    )
                if not ok:
                    return (
                        gr.update(visible=False),
                        gr.update(visible=False),
                        gr.update(visible=True, value="❌ Неверный пароль"),
                        gr.update(visible=True, value=""),
                        gr.update(visible=True)
                    )
                return (
                    gr.update(visible=True),  # load_btn
                    gr.update(visible=True),  # crl_table
                    gr.update(visible=False),  # msg_crl
                    gr.update(visible=False),  # admin_pwd2
                    gr.update(visible=False)  # login_btn2
                )

            login_btn2.click(
                fn=unlock_crl,
                inputs=admin_pwd2,
                outputs=[load_btn, crl_table, msg_crl, admin_pwd2, login_btn2]
            )

            load_btn.click(
                fn=fetch_crl_ui,
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
