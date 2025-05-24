# src/client/ui.py

import requests
import gradio as gr
from utils import generate_csr_and_issue, revoke_cert, get_crl, get_issuer_pubkey
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

        # 4. OCSP проверка
        with gr.Tab("OCSP проверка"):
            gr.Markdown("**Введите серийный номер и узнайте статус сертификата**")

            with gr.Row():
                serial_input = gr.Textbox(label="Серийный номер", placeholder="например: 1234567890")
                check_btn = gr.Button("Проверить")

            status_output = gr.Textbox(label="Статус", lines=1)
            issuer_output = gr.Textbox(label="Кто выпускал", lines=1)
            pubkey_output = gr.Textbox(label="Публичный ключ УЦ (PEM)", lines=4)
            sig_output = gr.Textbox(label="Подпись ответа (base64)", lines=3)

            def run_ocsp_check(serial_number):
                try:
                    result = check_ocsp_status(serial_number.strip())
                    return (
                        result.get("status", "неизвестно"),
                        result.get("issuer", ""),
                        result.get("issuer_public_key", ""),
                        result.get("signature", "")
                    )
                except Exception as e:
                    return (f"❌ Ошибка: {e}", "", "", "")

            check_btn.click(
                fn=run_ocsp_check,
                inputs=[serial_input],
                outputs=[status_output, issuer_output, pubkey_output, sig_output]
            )
            gr.Markdown("**Получить публичный ключ любого УЦ:**")

            issuer_select = gr.Dropdown(
                choices=["Root CA", "Intermediate CA 1", "Intermediate CA 2"],
                label="Выберите УЦ"
            )
            show_btn = gr.Button("Получить ключ")
            hide_btn = gr.Button("Скрыть ключ", visible=False)

            issuer_key_output = gr.Textbox(label="Публичный ключ УЦ (PEM)", lines=6, visible=False)

            def show_issuer_pubkey(issuer_choice):
                try:
                    key = get_issuer_pubkey(issuer_choice)
                    return key, gr.update(visible=True), gr.update(visible=True)
                except Exception as e:
                    return f"❌ Ошибка: {e}", gr.update(visible=True), gr.update(visible=False)

            def hide_issuer_key():
                return gr.update(visible=False), gr.update(visible=False)

            # Показать ключ
            show_btn.click(
                fn=show_issuer_pubkey,
                inputs=[issuer_select],
                outputs=[issuer_key_output, issuer_key_output, hide_btn]
            )

            # Скрыть ключ
            hide_btn.click(
                fn=hide_issuer_key,
                inputs=None,
                outputs=[issuer_key_output, hide_btn]
            )

            # 5. Руководство
        with gr.Tab("Руководство"):
            gr.Markdown("""
        ## Руководство по использованию

        **1. Выпуск сертификата X.509**  
        Перейдите во вкладку **«Выпуск X.509»**, заполните поля (CN, организация, email и т.д.) и нажмите кнопку **«Выпустить»**.  
        После этого отобразится сгенерированный сертификат и приватный ключ.  
        Также вы увидите его серийный номер — сохраните его, он нужен для отзыва или проверки.

        **2. Отзыв сертификата**  
        Введите пароль админа.
        Введите серийный номер сертификата и причину отзыва, нажмите **«Отозвать»**.  
        Вы получите подтверждение отзыва.

        **3. Список отозванных сертификатов (CRL)**
        Введите пароль админа.
        Нажмите кнопку **«Загрузить CRL»**, чтобы получить таблицу всех отозванных сертификатов с причинами и датами.

        **4. Проверка статуса сертификата (OCSP)**  
        Во вкладке **«OCSP проверка»** введите серийный номер сертификата и нажмите **«Проверить»**.  
        Вы увидите:
        - Статус: `good`, `revoked` или `unknown`
        - Кто выдал сертификат
        - Публичный ключ УЦ
        - Цифровую подпись ответа
        Ещё можно получить публичные ключи каждого из УЦ:
        Выберите УЦ, ключ которого хотите получить.
        Нажмите кнопку **«Получить ключ»**.
        Можете скрыть ключ нажатием на кнопку.

                    """)

    return demo
