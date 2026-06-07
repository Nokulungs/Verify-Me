import smtplib
from email.mime.text import MIMEText

GMAIL_USER = 'nokulungabembe@gmail.com'   # your sending account
GMAIL_PASS = 'mxio exxl lngw bbfi'        # your 16-char app password (with spaces is fine)
RECIPIENT  = 'nokulungaokuhle43@gmail.com'       # where it should arrive

msg = MIMEText('Test email from VerifyMe Flask app.')
msg['Subject'] = 'VerifyMe SMTP Test'
msg['From']    = GMAIL_USER
msg['To']      = RECIPIENT

try:
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.set_debuglevel(1)       # prints every SMTP conversation
        server.ehlo()
        server.starttls()
        server.login(GMAIL_USER, GMAIL_PASS)
        server.sendmail(GMAIL_USER, RECIPIENT, msg.as_string())
    print('\n✅ Email sent successfully')
except Exception as e:
    print(f'\n❌ Failed: {e}')