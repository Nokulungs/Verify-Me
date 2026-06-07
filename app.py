from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'super_secure_verifyme_key'

# --- Flask-Mail Configuration ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'nokulungabembe@gmail.com'
app.config['MAIL_PASSWORD'] = 'mxio exxl lngw bbfi'        # Your 16-char app password
app.config['MAIL_DEFAULT_SENDER'] = ('VerifyMe Portal', 'nokulungabembe@gmail.com')

mail = Mail(app)

@app.route('/')
def index():
    return render_template('index.html')

# --- Form Processing ---
@app.route('/submit-verification', methods=['POST'])
def submit_verification():

    # 1. Applicant type from hidden field
    applicant_type    = request.form.get('applicant_type')
    verification_type = request.form.get('verification_type')
    verification_volume = request.form.get('verification_volume')
    additional_notes  = request.form.get('additional_notes') or 'No additional notes provided.'

    # 2. Pull fields based on individual vs company toggle
    if applicant_type == 'individual':
        client_name   = request.form.get('individual_name')
        client_email  = request.form.get('individual_email')
        id_number     = request.form.get('individual_id') or 'Not provided'
        unique_identifier = f"<b>ID Number:</b> {id_number}"
        profile_label = 'Individual Applicant'
    else:
        client_name   = request.form.get('company_name')
        client_email  = request.form.get('company_email')
        contact_person = request.form.get('company_contact') or 'Not provided'
        unique_identifier = f"<b>Contact Person:</b> {contact_person}"
        profile_label = 'Corporate / Company Account'

    # 3. Email subject
    subject = f"New Verification Request — {client_name} | {verification_type}"

    # 4. HTML email body
    html_content = f"""
    <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e3e7e4; border-radius: 8px; background-color: #ffffff;">
        
        <div style="background-color: #2a312c; padding: 24px 20px; text-align: center; border-radius: 6px 6px 0 0;">
            <h2 style="color: #ffffff; margin: 0; font-size: 22px; letter-spacing: 1px;">VerifyMe Technologies</h2>
            <p style="color: #4eb637; margin: 6px 0 0 0; font-size: 11px; text-transform: uppercase; letter-spacing: 2px;">New Verification Request</p>
        </div>

        <div style="padding: 24px 20px;">
            <p style="font-size: 15px; color: #2a312c; line-height: 1.6; margin-bottom: 20px;">
                A new verification request has been submitted via the VerifyMe portal. Details below:
            </p>

            <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                <tr style="background-color: #f8faf9;">
                    <td style="padding: 12px 14px; font-weight: bold; border-bottom: 1px solid #e3e7e4; color: #2a312c; width: 38%;">Account Type</td>
                    <td style="padding: 12px 14px; border-bottom: 1px solid #e3e7e4; color: #555;">{profile_label}</td>
                </tr>
                <tr>
                    <td style="padding: 12px 14px; font-weight: bold; border-bottom: 1px solid #e3e7e4; color: #2a312c;">Name</td>
                    <td style="padding: 12px 14px; border-bottom: 1px solid #e3e7e4; color: #555;">{client_name}</td>
                </tr>
                <tr style="background-color: #f8faf9;">
                    <td style="padding: 12px 14px; font-weight: bold; border-bottom: 1px solid #e3e7e4; color: #2a312c;">Email Address</td>
                    <td style="padding: 12px 14px; border-bottom: 1px solid #e3e7e4;">
                        <a href="mailto:{client_email}" style="color: #4eb637; font-weight: 700; text-decoration: none;">{client_email}</a>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 12px 14px; font-weight: bold; border-bottom: 1px solid #e3e7e4; color: #2a312c;">Identifier</td>
                    <td style="padding: 12px 14px; border-bottom: 1px solid #e3e7e4; color: #555;">{unique_identifier}</td>
                </tr>
                <tr style="background-color: #f8faf9;">
                    <td style="padding: 12px 14px; font-weight: bold; border-bottom: 1px solid #e3e7e4; color: #2a312c;">Verification Service</td>
                    <td style="padding: 12px 14px; border-bottom: 1px solid #e3e7e4; color: #2a312c; font-weight: 600;">{verification_type}</td>
                </tr>
                <tr>
                    <td style="padding: 12px 14px; font-weight: bold; border-bottom: 1px solid #e3e7e4; color: #2a312c;">Volume</td>
                    <td style="padding: 12px 14px; border-bottom: 1px solid #e3e7e4; color: #555;">{verification_volume}</td>
                </tr>
            </table>

            <div style="margin-top: 24px; padding: 16px; background-color: #f0f4f2; border-left: 4px solid #4eb637; border-radius: 4px;">
                <p style="margin: 0 0 6px 0; font-weight: bold; color: #2a312c; font-size: 13px;">Additional Notes</p>
                <p style="margin: 0; color: #555; font-size: 14px; line-height: 1.6; font-style: italic;">"{additional_notes}"</p>
            </div>

            <div style="margin-top: 24px; padding: 14px; background-color: #eef8e8; border-radius: 6px; text-align: center;">
                <p style="margin: 0; font-size: 13px; color: #2a312c;">
                    Reply directly to this email or click the address above to contact <strong>{client_name}</strong>.
                </p>
            </div>
        </div>

        <div style="border-top: 1px solid #e3e7e4; padding: 16px 20px; text-align: center; color: #aaa; font-size: 11px;">
            <p style="margin: 0;">Powered by InspHired Recruitment Solutions</p>
            <p style="margin: 4px 0 0 0;">CONFIDENTIAL — This message contains private candidate screening information.</p>
        </div>
    </div>
    """

    # 5. Send the email
    try:
        msg = Message(
            subject=subject,
            sender=('VerifyMe Portal', 'nokulungabembe@gmail.com'),
            recipients=['nokulungabembe@gmail.com'],   # you receive it
            reply_to=client_email                       # replying goes to the client
        )
        msg.html = html_content
        mail.send(msg)
        flash('Your verification request has been submitted successfully. We will be in touch shortly.', 'success')
    except Exception as e:
        print(f"[MAIL ERROR] {str(e)}")
        flash('Something went wrong sending your request. Please try calling us directly.', 'error')

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)