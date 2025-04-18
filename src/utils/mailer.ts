import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

// Create reusable transporter object using SMTP transport
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  },
});

/**
 * Send an email
 * @param to Recipient email address
 * @param subject Email subject
 * @param html HTML content of the email
 * @returns Promise that resolves when email is sent
 */
export const sendEmail = async (to: string, subject: string, html: string): Promise<boolean> => {
  try {
    const mailOptions = {
      from: `"SafeNest Security" <${process.env.SMTP_USER}>`,
      to,
      subject,
      html,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Email sent to ${to}`);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
  }
};

/**
 * Send a verification code email
 * @param to Recipient email address
 * @param verificationCode The verification code
 * @returns Promise that resolves when email is sent
 */
export const sendVerificationEmail = async (to: string, verificationCode: string): Promise<boolean> => {
  const subject = 'SafeNest Account Verification';
  const html = `
    <h1>SafeNest Account Verification</h1>
    <p>Thank you for registering with SafeNest. To complete your registration, please use the verification code below:</p>
    <h2 style="background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 24px;">${verificationCode}</h2>
    <p>This code will expire in 10 minutes.</p>
    <p>If you did not request this verification, please ignore this email.</p>
    <p>The SafeNest Team</p>
  `;

  return sendEmail(to, subject, html);
};

/**
 * Send an alert notification email
 * @param to Recipient email address
 * @param alertDetails Details about the alert
 * @returns Promise that resolves when email is sent
 */
export const sendAlertEmail = async (
  to: string, 
  alertDetails: { 
    homeName: string; 
    cameraName: string; 
    timestamp: Date;
  }
): Promise<boolean> => {
  const subject = 'SafeNest Alert: Potential Danger Detected';
  const html = `
    <h1>⚠️ SafeNest Alert: Potential Danger Detected</h1>
    <p>Our system has detected a potential danger situation at your property:</p>
    <ul>
      <li><strong>Home:</strong> ${alertDetails.homeName}</li>
      <li><strong>Camera:</strong> ${alertDetails.cameraName}</li>
      <li><strong>Time:</strong> ${alertDetails.timestamp.toLocaleString()}</li>
    </ul>
    <p>Please check your SafeNest dashboard immediately to review this alert.</p>
    <p>If this is an emergency, please contact emergency services.</p>
    <p>The SafeNest Team</p>
  `;

  return sendEmail(to, subject, html);
};
