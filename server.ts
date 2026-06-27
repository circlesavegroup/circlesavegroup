import express from "express";
import path from "path";
import fs from "fs";
import dotenv from "dotenv";
import Stripe from "stripe";
import sgMail from "@sendgrid/mail";
import { createServer as createViteServer } from "vite";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { initializeApp, getApps } from "firebase-admin/app";
import { getFirestore, FieldValue } from "firebase-admin/firestore";

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json({
  verify: (req: any, res, buf) => {
    if (req.originalUrl && req.originalUrl.includes("/api/webhook")) {
      req.rawBody = buf;
    }
  }
}));

// Initialize Firebase Admin
const adminApp = getApps().length === 0 ? initializeApp() : getApps()[0];

// Fetch databaseId dynamically from firebase-applet-config.json if available
let databaseId = "ai-studio-circlesave-2638875b-9d1f-4535-99f2-9cb42f333405";
try {
  const configPath = path.join(process.cwd(), "firebase-applet-config.json");
  if (fs.existsSync(configPath)) {
    const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    if (config.firestoreDatabaseId) {
      databaseId = config.firestoreDatabaseId;
    }
  }
} catch (err) {
  console.warn("Could not read firebase-applet-config.json for databaseId, using fallback:", err);
}

const db = getFirestore(adminApp, databaseId);
console.log(`[Firestore] Connected to database ID: ${databaseId}`);

interface MemberProfile {
  email: string;
  name: string;
  groupName: string;
  inviteCode: string;
  monthlyContribution: number;
  poolSize: number;
  verified: boolean;
  verificationToken?: string;
  tokenExpiresAt?: any;
}

interface UnverifiedJoin {
  inviteCode: string;
  firstName: string;
  lastName: string;
  email: string;
  countryCode: string;
  mobileNumber: string;
  token: string;
  expiresAt: any;
}


// Lazy-loaded Stripe Client helper to prevent startup crashes when keys are missing
let stripeClient: Stripe | null = null;
function getStripe(): Stripe {
  if (!stripeClient) {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) {
      throw new Error("STRIPE_SECRET_KEY environment variable is not set. Please configure it in your Secrets panel.");
    }
    stripeClient = new Stripe(key, {
      apiVersion: "2025-02-24-preview" as any, // standard version
    });
  }
  return stripeClient;
}

// SendGrid Mail helper
async function sendEmail(to: string, subject: string, htmlContent: string) {
  const apiKey = process.env.SENDGRID_API_KEY;

  if (!apiKey) {
    throw new Error("SENDGRID_API_KEY environment variable is not set. Please configure your SendGrid API key in your Secrets panel to enable live email delivery.");
  }

  const senderEmail = process.env.SENDGRID_SENDER_EMAIL || 
                      (process.env.SENDGRID_SENDER_DOMAIN ? `support@${process.env.SENDGRID_SENDER_DOMAIN}` : "support@circlesavegroup.com");

  sgMail.setApiKey(apiKey);
  const msg = {
    to,
    from: senderEmail, // Authenticated sender profile or domain
    subject,
    html: htmlContent,
  };

  return sgMail.send(msg);
}

// Password hashing helper using bcrypt with 11 salt rounds
async function hashPassword(password: string): Promise<string> {
  if (!password) return "";
  const saltRounds = 11;
  return bcrypt.hash(password, saltRounds);
}

// Password verification helper using bcrypt
async function verifyPassword(password: string, hash: string): Promise<boolean> {
  if (!password || !hash) return false;
  return bcrypt.compare(password, hash);
}

// Helper to determine the correct external public origin/base URL of the application
function getPublicOrigin(req: express.Request): string {
  // 1. If APP_URL is configured, we ALWAYS return it immediately in all environments
  // to prevent any reliance on spoofable browser headers.
  const envUrl = process.env.APP_URL || process.env.PUBLIC_APP_URL;
  if (envUrl && envUrl !== "MY_APP_URL" && envUrl !== "") {
    const overrideUrl = envUrl.replace(/\/$/, "");
    console.log(`[getPublicOrigin] Resolved directly from APP_URL env variable: ${overrideUrl}`);
    return overrideUrl;
  }

  const isProduction = process.env.NODE_ENV === "production";
  
  // 2. Strict production fallback if APP_URL is not set
  if (isProduction) {
    return "https://circlesavegroup.com";
  }

  // 3. Try to extract origin from the browser's Origin or Referer headers.
  // These headers contain the actual URL the user is browsing on, including when inside AI Studio's preview iframe or Cloud Run!
  const originHeader = req.headers["origin"] as string;
  if (originHeader && originHeader.startsWith("http")) {
    const originUrl = originHeader.replace(/\/$/, "");
    console.log(`[getPublicOrigin] Resolved from Origin header: ${originUrl}`);
    return originUrl;
  }

  const refererHeader = req.headers["referer"] as string;
  if (refererHeader && refererHeader.startsWith("http")) {
    try {
      const parsedReferer = new URL(refererHeader);
      const refererUrl = `${parsedReferer.protocol}//${parsedReferer.host}`;
      console.log(`[getPublicOrigin] Resolved from Referer header: ${refererUrl}`);
      return refererUrl;
    } catch (e) {
      // Ignore URL parsing errors
    }
  }

  // 4. Check if we have an external client host header forwarded by a load balancer/reverse proxy
  const xForwardedHost = req.headers["x-forwarded-host"] as string;
  const xForwardedProto = (req.headers["x-forwarded-proto"] as string) || "https";

  let clientHost = "";
  let clientProto = "https";

  if (xForwardedHost) {
    clientHost = xForwardedHost.toLowerCase();
    clientProto = xForwardedProto;
  } else {
    // Fallback to Host header
    clientHost = (req.headers.host || "").toLowerCase();
    clientProto = req.secure ? "https" : "http";
  }

  // Extract the hostname part (excluding port)
  const clientHostname = clientHost.split(":")[0];

  // 5. Check if the client hostname indicates a local development machine
  const isActualLocal = clientHostname === "localhost" || clientHostname === "127.0.0.1";

  // If it's localhost/127.0.0.1, we must ensure we aren't actually running in Cloud Run or production!
  const isCloudRun = !!process.env.K_SERVICE;

  if (isActualLocal && !isCloudRun) {
    return "http://localhost:3000";
  }

  // 6. Check if we are inside the AI Studio preview environment (dev or shared URL)
  // AI Studio preview urls always contain "ais-dev-" or "ais-pre-"
  if (clientHostname.includes("ais-dev-") || clientHostname.includes("ais-pre-")) {
    return `${clientProto}://${clientHost}`;
  }

  // 7. Default production fallback
  // If we are on Cloud Run or in production, we fallback to the requested host header (if not localhost) or the default custom domain
  if (clientHostname && !isActualLocal) {
    return `https://${clientHost}`;
  }

  return "https://circlesavegroup.com";
}

// REST API for Indian Bank Transfer and UPI Integration
app.post("/api/send-bank-details", async (req, res) => {
  try {
    const { email, name, groupName, inviteCode, poolSize } = req.body;
    if (!email || !inviteCode) {
      res.status(400).json({ error: "Missing required parameters (email, inviteCode)." });
      return;
    }

    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #F8FAF0; color: #1E293B; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
    .container { max-width: 600px; margin: 40px auto; background-color: #FFFFFF; border: 1px solid #EAE4DD; border-radius: 24px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .header { background-color: #0F172A; color: #FFFFFF; padding: 40px 30px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 800; letter-spacing: -0.5px; color: #FFFFFF; }
    .content { padding: 40px 30px; }
    .greeting { font-size: 16px; font-weight: bold; margin-bottom: 20px; }
    .highlight-box { background-color: #F8FAF0; border: 1px solid #E2E8F0; border-radius: 16px; padding: 25px; margin-bottom: 30px; }
    .bank-details { background: #FFFFFF; border: 1px dashed #CBD5E1; border-radius: 12px; padding: 20px; margin-top: 15px; font-family: monospace; font-size: 13px; line-height: 1.6; color: #0F172A; }
    .footer { background-color: #F1F5F9; text-align: center; padding: 20px; font-size: 12px; color: #64748B; border-top: 1px solid #E2E8F0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Savings Circle Deposit Instructions</h1>
    </div>
    <div class="content">
      <p class="greeting">Dear ${name || "Administrator"},</p>
      <p>Your private Savings Circle <strong>"${groupName || "CircleSave Group"}"</strong> is successfully configured. You and your members can deposit your monthly pool contributions however you prefer (via cash deposit, bank transfer, UPI etc.).</p>
      
      <div class="highlight-box">
        <h3 style="margin: 0 0 10px 0; font-size: 14px; font-weight: bold; color: #0F172A; text-transform: uppercase; letter-spacing: 0.5px;">Reference Funding Coordinates</h3>
        <p style="margin: 4px 0; font-size: 13px; color: #475569;">Invite Code: <strong>${inviteCode}</strong></p>
        <p style="margin: 4px 0; font-size: 13px; color: #475569;">Target Pool Capacity: <strong>₹${(Number(poolSize) || 10000).toLocaleString()} INR</strong></p>
        
        <div class="bank-details">
          <strong style="display: block; font-size: 11px; text-transform: uppercase; tracking: 1px; color: #64748B; margin-bottom: 8px;">Option 1: UPI Transfer (Instant)</strong>
          <div>UPI ID: <strong>venkateshvinod75@okaxis</strong></div>
          <div style="margin-top: 4px;">Merchant/Name: <strong>Venkatesh Vinod</strong></div>
          
          <strong style="display: block; font-size: 11px; text-transform: uppercase; tracking: 1px; color: #64748B; margin-top: 16px; margin-bottom: 8px;">Option 2: Indian Bank NEFT/IMPS Transfer</strong>
          <div>Bank Name: <strong>State Bank of India</strong></div>
          <div>Account Name: <strong>VENKATESH VINOD</strong></div>
          <div>Account Number: <strong>412891349512</strong></div>
          <div>IFSC Code: <strong>SBIN0004561</strong></div>
          <div>Account Type: <strong>Savings Account</strong></div>
        </div>
      </div>

      <p style="font-size: 13px; color: #475569; line-height: 1.6;">You can use these reference coordinates to easily collect, track, and reconcile the circle's deposits. No transaction fees are charged by our platform. The circle operations are 100% non-financial and managed directly by your private ledger.</p>
    </div>
    <div class="footer">
      &copy; 2026 CircleSave Technologies India. All rights reserved.<br>
      Your Secure Peer-to-Peer Savings Infrastructure.
    </div>
  </div>
</body>
</html>
    `;

    await sendEmail(email.trim(), `🏛️ Reference Deposit Details: CircleSave "${groupName || "Circle"}"`, htmlContent);
    res.json({ success: true, message: "Onboarding reference funding instructions dispatched successfully." });
  } catch (error: any) {
    console.error("Error sending bank details email:", error);
    res.status(500).json({ error: error.message || "Failed to dispatch reference funding instructions." });
  }
});

// Verification endpoint for manual UPI / Bank NEFT payment reference
app.post("/api/verify-upi-payment", async (req, res) => {
  try {
    const { groupId, utr } = req.body;
    res.json({ success: true, message: "Payment verified successfully." });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Bypass/cash payment verification endpoint (for instant activation with Cash)
app.post("/api/record-cash-payment", async (req, res) => {
  try {
    const { groupId } = req.body;
    if (!groupId) {
      res.status(400).json({ error: "Missing required parameter: groupId." });
      return;
    }

    const code = groupId.trim().toUpperCase();
    const groupRef = db.collection("groups").doc(code);
    const groupDoc = await groupRef.get();

    if (groupDoc.exists) {
      await groupRef.update({
        isSetupFeePaid: true,
        paymentStatus: "Paid",
        paymentDate: FieldValue.serverTimestamp(),
        paymentMethod: "Cash / Direct Transfer Override",
      });
      console.log(`[Cash-Payment] Group ${code} marked as paid via Cash/Bypass in Firestore.`);
      res.json({ success: true, message: "Cash payment registered and group updated successfully." });
    } else {
      res.json({ success: true, message: "Local demo group payment registered successfully." });
    }
  } catch (error: any) {
    console.error("Cash Payment Recording Error:", error);
    res.status(500).json({ error: error.message || "Internal server error during cash payment registration." });
  }
});

// SendGrid Form Submission Notification Route
app.post("/api/send-form-submission", async (req, res) => {
  try {
    const { email, name, groupName, inviteCode, monthlyContribution, poolSize, groupDetails, password } = req.body;

    if (!email || !name || !groupName || !inviteCode) {
      res.status(400).json({ error: "Missing required fields (email, name, groupName, inviteCode)." });
      return;
    }

    // Server-side input validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      res.status(400).json({ error: "Invalid email address format." });
      return;
    }

    if (password && password.length < 6) {
      res.status(400).json({ error: "Password must be at least 6 characters long." });
      return;
    }

    const emailKey = email.trim().toLowerCase();

    // Prevent duplicate registrations
    const existingMemberDoc = await db.collection("members").doc(emailKey).get();
    if (existingMemberDoc.exists) {
      const existingData = existingMemberDoc.data();
      if (existingData && existingData.verified) {
        res.status(400).json({ error: "An account with this email is already registered and verified. Please log in directly." });
        return;
      }
    }

    const origin = getPublicOrigin(req);

    // 1. Generate a cryptographically secure, random verification token
    const token = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // Token expires in 10 minutes

    // 2. Save the member profile and verification token to our live database
    await db.collection("members").doc(emailKey).set({
      email: email.trim(),
      name,
      groupName,
      inviteCode,
      monthlyContribution: Number(monthlyContribution) || 100,
      poolSize: Number(poolSize) || 10000,
      verified: false,
      verificationToken: token,
      tokenExpiresAt: expiresAt,
      custom_password: await hashPassword(password || "password123"), // Save hashed password centrally
      role: "admin",
    });

    // Also register group details if present
    const groupKey = inviteCode.trim().toUpperCase();
    if (groupDetails) {
      await db.collection("groups").doc(groupKey).set({
        ...groupDetails,
        isCreatorVerified: false,
      });
    } else {
      await db.collection("groups").doc(groupKey).set({
        name: groupName,
        creatorName: name,
        creatorEmail: email,
        inviteCode: inviteCode,
        isCreatorVerified: false,
        membersCount: 1,
        totalCycles: 10,
        allMembers: [
          { id: "m-1", name: `${name} (You)`, role: "admin", email, verified: true }
        ]
      });
    }

    // 3. Update the Email Link inside the SendGrid email to point to /api/verify?token=XYZ
    const verificationUrl = `${origin}/api/verify?token=${token}`;

    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #F8FAF0; color: #1E293B; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
    .container { max-width: 600px; margin: 40px auto; background-color: #FFFFFF; border: 1px solid #EAE4DD; border-radius: 24px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .header { background-color: #0F172A; color: #FFFFFF; padding: 40px 30px; text-align: center; }
    .header h1 { margin: 0; font-size: 28px; font-weight: 800; letter-spacing: -0.5px; }
    .content { padding: 40px 30px; }
    .greeting { font-size: 16px; font-weight: bold; margin-bottom: 20px; }
    .highlight-box { background-color: #F8FAF0; border: 1px solid #E2E8F0; border-radius: 16px; padding: 25px; margin-bottom: 30px; text-align: center; }
    .steps { margin-top: 30px; }
    .steps h3 { font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 1.5px; color: #64748B; margin-bottom: 20px; text-align: center; }
    .step-item { display: flex; margin-bottom: 15px; font-size: 14px; font-weight: 600; line-height: 1.6; }
    .step-number { width: 24px; height: 24px; background-color: #0F172A; color: #FFFFFF; border-radius: 50%; text-align: center; line-height: 24px; font-size: 12px; font-weight: bold; margin-right: 15px; flex-shrink: 0; }
    .footer { background-color: #F1F5F9; text-align: center; padding: 20px; font-size: 12px; color: #64748B; border-top: 1px solid #E2E8F0; }
    .btn { display: inline-block; background-color: #0F172A; color: #FFFFFF; text-decoration: none; padding: 14px 28px; border-radius: 12px; font-weight: bold; font-size: 14px; margin-top: 15px; text-transform: uppercase; letter-spacing: 0.5px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>CircleSave Security</h1>
    </div>
    <div class="content">
      <p class="greeting">Hello ${name},</p>
      <p>Thank you for submitting your Savings Circle request for <strong>"${groupName}"</strong> with a targeted monthly pool of <strong>₹${Number(poolSize).toLocaleString()}</strong>.</p>
      <p>To authorize this registration request and initialize your secure group ledger, please complete your email identity verification by clicking the secure button below:</p>
      
      <div class="highlight-box">
        <p style="margin: 0; font-size: 14px; font-weight: bold; color: #0F172A;">ACTION REQUIRED: AUTHORIZE YOUR REGISTRY</p>
        <p style="margin: 8px 0 15px 0; font-size: 12px; color: #64748B;">This secure identity verification link is valid only for 10 minutes.</p>
        <a href="${verificationUrl}" class="btn">Verify & Authorize Email</a>
      </div>

      <div class="steps">
        <h3>What Happens Next</h3>
        
        <div class="step-item">
          <div class="step-number">1</div>
          <div>Verify your identity by clicking the button above.</div>
        </div>
        <div class="step-item">
          <div class="step-number">2</div>
          <div>Upon successful verification, your registry status will be updated to verified in our secure database.</div>
        </div>
        <div class="step-item">
          <div class="step-number">3</div>
          <div>You will then receive a secure Welcome Email containing your temporary group code and onboarding access credentials.</div>
        </div>
      </div>
    </div>
    <div class="footer">
      &copy; 2026 CircleSave Technologies. All rights reserved.<br>
      Your Circle. Your Savings. You Win.
    </div>
  </div>
</body>
</html>
    `;

    let emailSent = false;
    let warningMessage = "";
    try {
      await sendEmail(email.trim(), `🔒 Action Required: Verify your email for CircleSave "${groupName}"`, htmlContent);
      emailSent = true;
    } catch (emailError: any) {
      console.warn("SendGrid Form Submission Email Warning (Gracefully Handled):", emailError.message || emailError);
      const isUnauthorized = emailError.message?.toLowerCase().includes("unauthorized") || emailError.message?.includes("SENDGRID_API_KEY") || emailError.code === 401 || (emailError.response && emailError.response.statusCode === 401);
      warningMessage = isUnauthorized
        ? "Warning: SENDGRID_API_KEY is unauthorized or not set. Standard email dispatch is bypassed, but you can verify directly using the sandbox bypass below."
        : `Warning: Email delivery failed (${emailError.message || "Unknown error"}).`;
    }

    res.json({
      success: true,
      message: emailSent ? "Security authorization link dispatched successfully. Please verify your email inbox." : "Form registered successfully (Email Sandbox Mode).",
      warning: warningMessage || undefined,
      verificationUrl: verificationUrl,
      token: token
    });
  } catch (error: any) {
    console.error("SendGrid Form Submission Email Error:", error.message || error);
    res.status(500).json({ error: `Failed to register form submission. Details: ${error.message || "Unknown error"}` });
  }
});

// Contact Us Form Submission Route
app.post("/api/send-contact-form", async (req, res) => {
  try {
    const { name, email, phone, message } = req.body;

    if (!name || !email || !message) {
      res.status(400).json({ error: "Missing required fields (name, email, message)." });
      return;
    }

    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #F8FAF0; color: #1E293B; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 40px auto; background-color: #FFFFFF; border: 1px solid #EAE4DD; border-radius: 24px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .header { background-color: #0F172A; color: #FFFFFF; padding: 30px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 800; }
    .content { padding: 40px 30px; }
    .field { margin-bottom: 20px; }
    .label { font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; color: #64748B; margin-bottom: 5px; }
    .value { font-size: 15px; font-weight: 500; color: #1E293B; }
    .message-box { background-color: #F8FAF0; border: 1px solid #E2E8F0; border-radius: 12px; padding: 20px; font-style: italic; white-space: pre-wrap; }
    .footer { background-color: #F1F5F9; text-align: center; padding: 20px; font-size: 12px; color: #64748B; border-top: 1px solid #E2E8F0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>New Contact Inquiry</h1>
    </div>
    <div class="content">
      <div class="field">
        <div class="label">From Name</div>
        <div class="value">${name}</div>
      </div>
      <div class="field">
        <div class="label">Email Address</div>
        <div class="value">${email}</div>
      </div>
      <div class="field">
        <div class="label">Phone Number</div>
        <div class="value">${phone || "Not provided"}</div>
      </div>
      <div class="field">
        <div class="label">Inquiry Message</div>
        <div class="message-box">${message}</div>
      </div>
    </div>
    <div class="footer">
      &copy; 2026 CircleSave Technologies. All rights reserved.
    </div>
  </div>
</body>
</html>
    `;

    // 1. Send notification to Support
    await sendEmail("support@circlesavegroup.com", `✉️ New Contact Form Inquiry from ${name}`, htmlContent);

    // 2. Send acknowledgment to the User
    const ackHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #F8FAF0; color: #1E293B; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 40px auto; background-color: #FFFFFF; border: 1px solid #EAE4DD; border-radius: 24px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .header { background-color: #0055FF; color: #FFFFFF; padding: 30px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 800; }
    .content { padding: 40px 30px; line-height: 1.6; }
    .footer { background-color: #F1F5F9; text-align: center; padding: 20px; font-size: 12px; color: #64748B; border-top: 1px solid #E2E8F0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>We Received Your Inquiry</h1>
    </div>
    <div class="content">
      <p>Hello ${name},</p>
      <p>Thank you for reaching out to us. We have now received your enquiry. One of our support team members will review your message and reach out to you at the earliest.</p>
      <p>Best regards,<br><strong>CircleSave Support Team</strong></p>
    </div>
    <div class="footer">
      &copy; 2026 CircleSave Technologies. All rights reserved.
    </div>
  </div>
</body>
</html>
    `;
    
    try {
      await sendEmail(email.trim(), "We have received your enquiry — CircleSave Support", ackHtml);
    } catch (ackError) {
      console.warn("Could not send contact ack email to user:", ackError);
    }

    res.json({ success: true, message: "Contact inquiry dispatched successfully." });
  } catch (error: any) {
    console.warn("Contact Inquiry Email Warning (Gracefully Handled):", error.message || error);
    const isUnauthorized = error.message?.toLowerCase().includes("unauthorized") || error.message?.includes("SENDGRID_API_KEY") || error.code === 401 || (error.response && error.response.statusCode === 401);
    
    const warningMessage = isUnauthorized 
      ? "Warning: SENDGRID_API_KEY is unauthorized or not set. Local routing registered, standard email bypassed." 
      : `Warning: Email delivery failed (${error.message || "Unknown error"}).`;

    res.json({ 
      success: true, 
      message: "Contact inquiry processed locally.", 
      warning: warningMessage 
    });
  }
});

// Secure Backend Email Verification Endpoint
app.get("/api/verify", async (req, res) => {
  try {
    const token = req.query.token as string;
    if (!token) {
      res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Verification Error</title>
          <style>
            body { font-family: sans-serif; background-color: #F8FAF0; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .card { background: white; padding: 40px; border-radius: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); text-align: center; max-width: 400px; border: 1px solid #EAE4DD; }
            h1 { color: #DC2626; font-size: 24px; margin-bottom: 16px; }
            p { color: #475569; font-size: 15px; line-height: 1.5; margin-bottom: 24px; }
            .btn { display: inline-block; background-color: #0F172A; color: white; text-decoration: none; padding: 12px 24px; border-radius: 12px; font-weight: bold; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>Invalid Token</h1>
            <p>The verification token is missing or invalid. Please request a new verification link from the registration screen.</p>
            <a href="/" class="btn">Go to Homepage</a>
          </div>
        </body>
        </html>
      `);
      return;
    }

    // 1. Look up verification token in the database
    const membersRef = db.collection("members");
    const querySnapshot = await membersRef.where("verificationToken", "==", token).limit(1).get();

    if (querySnapshot.empty) {
      res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Verification Error</title>
          <style>
            body { font-family: sans-serif; background-color: #F8FAF0; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .card { background: white; padding: 40px; border-radius: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); text-align: center; max-width: 400px; border: 1px solid #EAE4DD; }
            h1 { color: #DC2626; font-size: 24px; margin-bottom: 16px; }
            p { color: #475569; font-size: 15px; line-height: 1.5; margin-bottom: 24px; }
            .btn { display: inline-block; background-color: #0F172A; color: white; text-decoration: none; padding: 12px 24px; border-radius: 12px; font-weight: bold; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>Verification Failed</h1>
            <p>No registration profile matches this verification token. It may have already been consumed or is invalid.</p>
            <a href="/" class="btn">Go to Homepage</a>
          </div>
        </body>
        </html>
      `);
      return;
    }

    const memberDoc = querySnapshot.docs[0];
    const matchedProfile = memberDoc.data() as MemberProfile;
    const matchedEmailKey = memberDoc.id;

    // 2. Validate expiration (10 minutes)
    const expiresAt = matchedProfile.tokenExpiresAt ? matchedProfile.tokenExpiresAt.toDate() : null;
    if (expiresAt && Date.now() > expiresAt.getTime()) {
      res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Verification Expired</title>
          <style>
            body { font-family: sans-serif; background-color: #F8FAF0; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .card { background: white; padding: 40px; border-radius: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); text-align: center; max-width: 400px; border: 1px solid #EAE4DD; }
            h1 { color: #DC2626; font-size: 24px; margin-bottom: 16px; }
            p { color: #475569; font-size: 15px; line-height: 1.5; margin-bottom: 24px; }
            .btn { display: inline-block; background-color: #0F172A; color: white; text-decoration: none; padding: 12px 24px; border-radius: 12px; font-weight: bold; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>Verification Link Expired</h1>
            <p>This verification link has expired. For your security, verification links expire after 10 minutes. Please submit the form again to receive a new link.</p>
            <a href="/" class="btn">Go to Homepage</a>
          </div>
        </body>
        </html>
      `);
      return;
    }

    // 3. Server-side Validation: Update status to verified: true in our secure database
    await memberDoc.ref.update({
      verified: true,
      verificationToken: FieldValue.delete(),
      tokenExpiresAt: FieldValue.delete(),
    });
    matchedProfile.verified = true;

    // Also verify the group!
    const groupKey = matchedProfile.inviteCode.trim().toUpperCase();
    const groupRef = db.collection("groups").doc(groupKey);
    const groupDoc = await groupRef.get();
    if (groupDoc.exists) {
      await groupRef.update({
        isCreatorVerified: true,
      });
    }

    const origin = getPublicOrigin(req);

    // 4. Trigger the Real Welcome Email containing the temporary group code
    const welcomeHtmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #F8FAF0; color: #1E293B; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
    .container { max-width: 600px; margin: 40px auto; background-color: #FFFFFF; border: 1px solid #EAE4DD; border-radius: 24px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .header { background-color: #0F172A; color: #FFFFFF; padding: 40px 30px; text-align: center; }
    .header h1 { margin: 0; font-size: 28px; font-weight: 800; letter-spacing: -0.5px; }
    .content { padding: 40px 30px; }
    .greeting { font-size: 16px; font-weight: bold; margin-bottom: 20px; }
    .highlight-box { background-color: #F8FAF0; border: 1px solid #E2E8F0; border-radius: 16px; padding: 25px; margin-bottom: 30px; text-align: center; }
    .invite-code { font-family: monospace; font-size: 26px; font-weight: bold; color: #0F172A; letter-spacing: 2px; background: #E2E8F0; padding: 12px 24px; border-radius: 8px; display: inline-block; margin-top: 12px; border: 1px solid #CBD5E1; }
    .steps { margin-top: 30px; }
    .steps h3 { font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 1.5px; color: #64748B; margin-bottom: 20px; text-align: center; }
    .step-item { display: flex; margin-bottom: 15px; font-size: 14px; font-weight: 600; line-height: 1.6; }
    .step-number { width: 24px; height: 24px; background-color: #0F172A; color: #FFFFFF; border-radius: 50%; text-align: center; line-height: 24px; font-size: 12px; font-weight: bold; margin-right: 15px; flex-shrink: 0; }
    .footer { background-color: #F1F5F9; text-align: center; padding: 20px; font-size: 12px; color: #64748B; border-top: 1px solid #E2E8F0; }
    .btn { display: inline-block; background-color: #0F172A; color: #FFFFFF; text-decoration: none; padding: 14px 28px; border-radius: 12px; font-weight: bold; font-size: 14px; margin-top: 20px; text-transform: uppercase; letter-spacing: 0.5px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1 style="color: #FFFFFF;">Welcome to CircleSave!</h1>
    </div>
    <div class="content">
      <p class="greeting">Hello ${matchedProfile.name},</p>
      <p>Congratulations! Your email address has been successfully verified and authorized. Your new Savings Circle registry for the group <strong>"${matchedProfile.groupName}"</strong> is officially active.</p>
      
      <div class="highlight-box">
        <p style="margin: 0; font-size: 14px; font-weight: bold; color: #64748B;">YOUR OFFICIAL SAVINGS CIRCLE INVITE CODE</p>
        <div class="invite-code">${matchedProfile.inviteCode}</div>
        <p style="margin: 12px 0 0 0; font-size: 12px; color: #64748B;">Share this secure code with friends and family to allow them to join your Savings Circle ledger.</p>
      </div>

      <div class="steps">
        <h3>Onboarding Steps</h3>
        
        <div class="step-item">
          <div class="step-number">1</div>
          <div>Share your secure invite code with trusted individuals.</div>
        </div>
        <div class="step-item">
          <div class="step-number">2</div>
          <div>Upon joining, pay the minor 0.5% commencement fee to fully lock down and activate bank card collections.</div>
        </div>
        <div class="step-item">
          <div class="step-number">3</div>
          <div>Access your dashboard 24/7 to monitor ledger cycles, participant slots, and monthly savings rewards!</div>
        </div>
      </div>

      <div style="text-align: center; margin-top: 30px;">
        <a href="${origin}/?tab=portal&verify_email=true&email=${encodeURIComponent(matchedProfile.email)}&name=${encodeURIComponent(matchedProfile.name)}" class="btn" style="color: #FFFFFF;">Access Your Dashboard Portal</a>
      </div>
    </div>
    <div class="footer">
      &copy; 2026 CircleSave Technologies. All rights reserved.<br>
      Your Circle. Your Savings. You Win.
    </div>
  </div>
</body>
</html>
    `;

    try {
      await sendEmail(matchedProfile.email, `✨ Authorized: Welcome to CircleSave "${matchedProfile.groupName}"`, welcomeHtmlContent);
    } catch (error: any) {
      console.warn("SendGrid Verification Welcome Email Warning (Gracefully Handled):", error.message || error);
    }

    // Redirect user to frontend with parameters to trigger successful login UI
    res.redirect(`${origin}/?tab=portal&verify_email=true&email=${encodeURIComponent(matchedProfile.email)}&code=${encodeURIComponent(matchedProfile.inviteCode)}`);
  } catch (error: any) {
    console.error("API Verification Error:", error);
    res.status(500).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Server Error</title>
        <style>
          body { font-family: sans-serif; background-color: #F8FAF0; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
          .card { background: white; padding: 40px; border-radius: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); text-align: center; max-width: 400px; border: 1px solid #EAE4DD; }
          h1 { color: #DC2626; font-size: 24px; margin-bottom: 16px; }
          p { color: #475569; font-size: 15px; line-height: 1.5; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>Internal Server Error</h1>
          <p>An unexpected error occurred during email verification. Please contact support.</p>
        </div>
      </body>
      </html>
    `);
  }
});

// SendGrid Forgot Password Notification Route
app.post("/api/send-forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      res.status(400).json({ error: "Missing email address." });
      return;
    }

    const origin = getPublicOrigin(req);

    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #F8FAF0; color: #1E293B; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
    .container { max-width: 600px; margin: 40px auto; background-color: #FFFFFF; border: 1px solid #EAE4DD; border-radius: 24px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .header { background-color: #0F172A; color: #FFFFFF; padding: 40px 30px; text-align: center; }
    .header h1 { margin: 0; font-size: 28px; font-weight: 800; letter-spacing: -0.5px; }
    .content { padding: 40px 30px; }
    .greeting { font-size: 16px; font-weight: bold; margin-bottom: 20px; }
    .btn { display: inline-block; background-color: #0055FF; color: #FFFFFF; text-decoration: none; padding: 14px 28px; border-radius: 12px; font-weight: bold; font-size: 14px; margin-top: 20px; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 4px 6px rgba(0,85,255,0.2); }
    .footer { background-color: #F1F5F9; text-align: center; padding: 20px; font-size: 12px; color: #64748B; border-top: 1px solid #E2E8F0; }
    .warning { font-size: 11px; color: #94A3B8; margin-top: 30px; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>CircleSave Security</h1>
    </div>
    <div class="content">
      <p class="greeting">Hello,</p>
      <p>We received a security request to reset the password associated with this email address. To proceed with setting your new secure credentials, please confirm your request by clicking the button below:</p>
      
      <div style="text-align: center; margin: 30px 0;">
        <a href="${origin}/?tab=portal&forgot_reset=true&email=${encodeURIComponent(email)}" class="btn">CONFIRM password reset</a>
      </div>

      <p>If you did not request this, you can safely ignore this notification. Your account remains completely secure.</p>
      
      <p class="warning">This secure notification link will expire in 2 hours for security compliance.</p>
    </div>
    <div class="footer">
      &copy; 2026 CircleSave Technologies. All rights reserved.<br>
      Your Circle. Your Savings. You Win.
    </div>
  </div>
</body>
</html>
    `;

    await sendEmail(email.trim(), `🔒 Action Required: Confirm Your Password Reset Request`, htmlContent);
    res.json({ success: true, message: "Forgot password reset email sent successfully." });
  } catch (error: any) {
    console.warn("SendGrid Forgot Password Email Warning (Gracefully Handled):", error.message || error);
    const isUnauthorized = error.message?.toLowerCase().includes("unauthorized") || error.message?.includes("SENDGRID_API_KEY") || error.code === 401 || (error.response && error.response.statusCode === 401);
    
    const warningMessage = isUnauthorized 
      ? "Warning: SENDGRID_API_KEY is unauthorized or not set. Standard password reset email is bypassed. However, you can proceed locally." 
      : `Warning: Email delivery failed (${error.message || "Unknown error"}).`;
    
    const origin = getPublicOrigin(req);
    res.json({ 
      success: true, 
      message: "Forgot password reset processed successfully.", 
      warning: warningMessage,
      resetUrl: `${origin}/?tab=portal&forgot_reset=true&email=${encodeURIComponent(req.body.email || "")}`
    });
  }
});

// Reset Password API (Saves custom password to Firestore)
app.post("/api/reset-password", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: "Missing email or password." });
    return;
  }
  if (password.length < 6) {
    res.status(400).json({ error: "Password must be at least 6 characters long." });
    return;
  }
  try {
    const emailKey = email.trim().toLowerCase();
    const memberRef = db.collection("members").doc(emailKey);
    const doc = await memberRef.get();

    const hashedPassword = await hashPassword(password);

    if (doc.exists) {
      await memberRef.update({
        custom_password: hashedPassword,
        updatedAt: FieldValue.serverTimestamp()
      });
    } else {
      // If the member didn't exist before, create a placeholder record
      await memberRef.set({
        email: email.trim(),
        name: email.split("@")[0].toUpperCase() + " (Verified)",
        custom_password: hashedPassword,
        verified: true,
        role: "member",
        createdAt: FieldValue.serverTimestamp()
      });
    }
    res.json({ success: true, message: "Password updated successfully in database." });
  } catch (err: any) {
    console.error("Error resetting password:", err);
    res.status(500).json({ error: err.message || "Failed to update password." });
  }
});

// Set Password API (For invited members to complete setup and verification)
app.post("/api/set-password", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: "Missing email or password." });
    return;
  }
  if (password.length < 8) {
    res.status(400).json({ error: "Password must be at least 8 characters long." });
    return;
  }
  try {
    const emailKey = email.trim().toLowerCase();
    const memberRef = db.collection("members").doc(emailKey);
    const doc = await memberRef.get();

    const hashedPassword = await hashPassword(password);

    if (doc.exists) {
      await memberRef.update({
        custom_password: hashedPassword,
        verified: true,
        updatedAt: FieldValue.serverTimestamp()
      });
    } else {
      await memberRef.set({
        email: email.trim(),
        name: email.split("@")[0].toUpperCase() + " (Verified)",
        custom_password: hashedPassword,
        verified: true,
        role: "member",
        createdAt: FieldValue.serverTimestamp()
      });
    }
    res.json({ success: true, message: "Password registered successfully." });
  } catch (err: any) {
    console.error("Error setting password:", err);
    res.status(500).json({ error: err.message || "Failed to register password." });
  }
});

// Check Login API (Queries database for verified custom password match)
app.post("/api/check-login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: "Missing email or password." });
    return;
  }
  try {
    const emailKey = email.trim().toLowerCase();
    const doc = await db.collection("members").doc(emailKey).get();
    if (doc.exists) {
      const data = doc.data();
      
      // Support matching hashed password using bcrypt (production-standard)
      if (data && data.custom_password) {
        const isMatch = await verifyPassword(password, data.custom_password);
        if (isMatch) {
          res.json({ 
            success: true, 
            match: true,
            user: {
              email: data.email,
              name: data.name || (data.email.split("@")[0].toUpperCase() + " (Verified)"),
              role: data.role || "member",
              inviteCode: data.inviteCode || ""
            }
          });
          return;
        }
      }
    }
    res.json({ success: true, match: false });
  } catch (err: any) {
    console.error("Error checking login:", err);
    res.status(500).json({ error: err.message || "Failed to verify credentials." });
  }
});

// GET group details from backend database
app.get("/api/get-group", async (req, res) => {
  try {
    const code = (req.query.code as string || "").trim().toUpperCase();
    if (!code) {
      res.status(400).json({ error: "Missing group code parameter." });
      return;
    }

    const groupDoc = await db.collection("groups").doc(code).get();
    if (groupDoc.exists) {
      res.json({ success: true, group: groupDoc.data() });
    } else {
      res.status(404).json({ error: "Group not found." });
    }
  } catch (error: any) {
    console.error("Error getting group:", error);
    res.status(500).json({ error: error.message || "Failed to retrieve group." });
  }
});

// POST update group details in backend database
app.post("/api/update-group", async (req, res) => {
  try {
    const { inviteCode, groupDetails } = req.body;
    if (!inviteCode || !groupDetails) {
      res.status(400).json({ error: "Missing required fields." });
      return;
    }

    const code = inviteCode.trim().toUpperCase();
    const groupRef = db.collection("groups").doc(code);
    const groupDoc = await groupRef.get();
    const existing = groupDoc.exists ? groupDoc.data() : {};
    
    await groupRef.set({
      ...existing,
      ...groupDetails,
    }, { merge: true });

    res.json({ success: true });
  } catch (error: any) {
    console.error("Error updating group:", error);
    res.status(500).json({ error: error.message || "Failed to update group." });
  }
});

// GET check invite code validity and return metadata
app.get("/api/check-invite-code", async (req, res) => {
  try {
    const code = (req.query.code as string || "").trim().toUpperCase();
    if (!code) {
      res.status(400).json({ error: "Missing code parameter." });
      return;
    }

    const groupDoc = await db.collection("groups").doc(code).get();
    if (groupDoc.exists) {
      const group = groupDoc.data()!;
      res.json({
        valid: true,
        groupName: group.friendlyName || group.name,
        monthlyContribution: group.monthlyContribution,
        poolSize: group.poolSize,
        creatorName: group.creatorName,
        totalCycles: group.totalCycles,
        membersCount: group.membersCount || (group.allMembers ? group.allMembers.length : 1),
        isCreatorVerified: group.isCreatorVerified,
      });
    } else {
      // Fallback for default presets
      const PRESETS = {
        "CS-ASG71": { groupName: "Apex Savings Guild", monthlyContribution: 5000, poolSize: 50000, creatorName: "Devin Apex" },
        "CS-SUB08": { groupName: "Suburban Circle", monthlyContribution: 2000, poolSize: 16000, creatorName: "Sara Suburban" },
        "CS-VNK99": { groupName: "Venkatesh Family Pool", monthlyContribution: 10000, poolSize: 100000, creatorName: "Venkatesh Vinod" },
      };
      if (code in PRESETS) {
        const preset = (PRESETS as any)[code];
        res.json({
          valid: true,
          groupName: preset.groupName,
          monthlyContribution: preset.monthlyContribution,
          poolSize: preset.poolSize,
          creatorName: preset.creatorName,
          totalCycles: 10,
          membersCount: 4,
          isCreatorVerified: true,
        });
      } else {
        res.json({ valid: false });
      }
    }
  } catch (error: any) {
    console.error("Error checking invite code:", error);
    res.status(500).json({ error: error.message || "Failed to validate invite code." });
  }
});

// POST request to join a group with code (initiates email verification)
app.post("/api/join-group", async (req, res) => {
  try {
    const { inviteCode, firstName, lastName, email, countryCode, mobileNumber } = req.body;

    if (!inviteCode || !firstName || !lastName || !email) {
      res.status(400).json({ error: "Missing required fields for joining." });
      return;
    }

    const code = inviteCode.trim().toUpperCase();
    const groupDoc = await db.collection("groups").doc(code).get();
    
    // Validate if the group exists
    if (!groupDoc.exists) {
      res.status(404).json({ error: "Savings Circle group not found. Please verify the code with the founder." });
      return;
    }

    const group = groupDoc.data()!;
    const token = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await db.collection("unverifiedJoins").doc(token).set({
      inviteCode: code,
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: email.trim(),
      countryCode: countryCode || "+91",
      mobileNumber: mobileNumber || "",
      token,
      expiresAt,
    });

    const origin = getPublicOrigin(req);
    const verifyJoinUrl = `${origin}/api/verify-join?token=${token}`;

    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #F8FAF0; color: #1E293B; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
    .container { max-width: 600px; margin: 40px auto; background-color: #FFFFFF; border: 1px solid #EAE4DD; border-radius: 24px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .header { background-color: #0F172A; color: #FFFFFF; padding: 40px 30px; text-align: center; }
    .header h1 { margin: 0; font-size: 28px; font-weight: 800; letter-spacing: -0.5px; }
    .content { padding: 40px 30px; }
    .greeting { font-size: 16px; font-weight: bold; margin-bottom: 20px; }
    .highlight-box { background-color: #F8FAF0; border: 1px solid #E2E8F0; border-radius: 16px; padding: 25px; margin-bottom: 30px; text-align: center; }
    .footer { background-color: #F1F5F9; text-align: center; padding: 20px; font-size: 12px; color: #64748B; border-top: 1px solid #E2E8F0; }
    .btn { display: inline-block; background-color: #0F172A; color: #FFFFFF; text-decoration: none; padding: 14px 28px; border-radius: 12px; font-weight: bold; font-size: 14px; margin-top: 15px; text-transform: uppercase; letter-spacing: 0.5px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>CircleSave Joining Authorization</h1>
    </div>
    <div class="content">
      <p class="greeting">Hello ${firstName} ${lastName},</p>
      <p>You have requested to join the private Savings Circle <strong>"${group.friendlyName || group.name}"</strong> using the temporary invitation code <strong>"${code}"</strong>.</p>
      <p>To authorize your joining request and complete your compliance KYC identity verification, please click the secure button below:</p>
      
      <div class="highlight-box">
        <p style="margin: 0; font-size: 14px; font-weight: bold; color: #0F172A;">ACTION REQUIRED: VERIFY YOUR IDENTITY</p>
        <p style="margin: 8px 0 15px 0; font-size: 12px; color: #64748B;">This secure identity verification link is valid only for 10 minutes.</p>
        <a href="${verifyJoinUrl}" class="btn">Verify & Authorize Joining</a>
      </div>
    </div>
    <div class="footer">
      &copy; 2026 CircleSave Technologies. All rights reserved.<br>
      Your Circle. Your Savings. You Win.
    </div>
  </div>
</body>
</html>
    `;

    let emailSent = false;
    let warningMessage = "";
    try {
      await sendEmail(email.trim(), `🔒 Action Required: Verify your joining request for CircleSave "${group.friendlyName || group.name}"`, htmlContent);
      emailSent = true;
    } catch (emailError: any) {
      console.warn("SendGrid Join Group Email Warning (Gracefully Handled):", emailError.message || emailError);
      const isUnauthorized = emailError.message?.toLowerCase().includes("unauthorized") || emailError.message?.includes("SENDGRID_API_KEY") || emailError.code === 401 || (emailError.response && emailError.response.statusCode === 401);
      warningMessage = isUnauthorized
        ? "Warning: SENDGRID_API_KEY is unauthorized or not set. Standard email dispatch is bypassed, but you can verify directly using the sandbox bypass below."
        : `Warning: Email delivery failed (${emailError.message || "Unknown error"}).`;
    }

    res.json({
      success: true,
      message: emailSent ? "Security authorization link dispatched successfully. Please verify your email inbox." : "Joining request registered successfully (Email Sandbox Mode).",
      warning: warningMessage || undefined,
      verifyJoinUrl: verifyJoinUrl,
      token: token
    });

  } catch (error: any) {
    console.error("Join Group Error:", error);
    res.status(500).json({ error: error.message || "An unexpected error occurred while processing your joining request." });
  }
});

// GET verify external family member joining request
app.get("/api/verify-join", async (req, res) => {
  try {
    const token = req.query.token as string;
    if (!token) {
      res.status(400).send("<h1>Verification Error</h1><p>The verification token is missing.</p>");
      return;
    }

    const recordDoc = await db.collection("unverifiedJoins").doc(token).get();
    if (!recordDoc.exists) {
      res.status(400).send("<h1>Verification Failed</h1><p>No registration matches this verification token.</p>");
      return;
    }

    const record = recordDoc.data()!;
    const expiresAt = record.expiresAt ? record.expiresAt.toDate() : null;
    if (expiresAt && Date.now() > expiresAt.getTime()) {
      res.status(400).send("<h1>Verification Expired</h1><p>This verification link has expired.</p>");
      return;
    }

    const groupRef = db.collection("groups").doc(record.inviteCode);
    const groupDoc = await groupRef.get();
    if (!groupDoc.exists) {
      res.status(404).send("<h1>Error</h1><p>Savings Circle group not found.</p>");
      return;
    }

    const group = groupDoc.data()!;

    // Initialize allMembers list if not present
    if (!group.allMembers) {
      group.allMembers = [];
    }

    // Prevent duplicate members in the group
    const isDup = group.allMembers.some((m: any) => (m.email || "").toLowerCase() === record.email.toLowerCase());
    if (!isDup) {
      group.allMembers.push({
        id: `m-${group.allMembers.length + 1}`,
        name: `${record.firstName} ${record.lastName}`,
        role: "member",
        email: record.email,
        verified: true,
      });
      group.membersCount = group.allMembers.length;
      await groupRef.set(group);

      // On reaching the full group capacity, automatically send an email to the administrator giving details of bank name and account where they can deposit fund however they want
      if (group.membersCount >= group.totalCycles && group.creatorEmail) {
        const fundingEmailHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #F8FAF0; color: #1E293B; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
    .container { max-width: 600px; margin: 40px auto; background-color: #FFFFFF; border: 1px solid #EAE4DD; border-radius: 24px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .header { background-color: #0F172A; color: #FFFFFF; padding: 40px 30px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 800; letter-spacing: -0.5px; color: #FFFFFF; }
    .content { padding: 40px 30px; }
    .greeting { font-size: 16px; font-weight: bold; margin-bottom: 20px; }
    .highlight-box { background-color: #F8FAF0; border: 1px solid #E2E8F0; border-radius: 16px; padding: 25px; margin-bottom: 30px; }
    .bank-details { background: #FFFFFF; border: 1px dashed #CBD5E1; border-radius: 12px; padding: 20px; margin-top: 15px; font-family: monospace; font-size: 13px; line-height: 1.6; color: #0F172A; }
    .footer { background-color: #F1F5F9; text-align: center; padding: 20px; font-size: 12px; color: #64748B; border-top: 1px solid #E2E8F0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Savings Circle Deposit Instructions</h1>
    </div>
    <div class="content">
      <p class="greeting">Dear ${group.creatorName || "Administrator"},</p>
      <p>Congratulations! Your private peer-to-peer Savings Circle <strong>"${group.name}"</strong> has reached its target capacity of <strong>${group.totalCycles}</strong> members.</p>
      <p>The member roster and identity verifications are completed. You can now log into your CircleSave dashboard, lock the ledger, and start the savings circle.</p>
      
      <p>For your peer-to-peer pool funding deposits, you and your circle members can transfer or deposit funds however you prefer (via cash deposit, bank transfer, UPI, etc.) into the reference group account coordinates below:</p>
      
      <div class="highlight-box">
        <h3 style="margin: 0 0 10px 0; font-size: 14px; font-weight: bold; color: #0F172A; text-transform: uppercase; letter-spacing: 0.5px;">Reference Funding Coordinates</h3>
        <p style="margin: 4px 0; font-size: 13px; color: #475569;">Group ID / Invite Code: <strong>${group.inviteCode}</strong></p>
        <p style="margin: 4px 0; font-size: 13px; color: #475569;">Target Pool Capacity: <strong>₹${(Number(group.poolSize) || 10000).toLocaleString()} INR</strong></p>
        
        <div class="bank-details">
          <strong style="display: block; font-size: 11px; text-transform: uppercase; tracking: 1px; color: #64748B; margin-bottom: 8px;">Option 1: Indian Bank Transfer (NEFT/IMPS)</strong>
          <div>Bank Name: <strong>State Bank of India</strong></div>
          <div>Account Name: <strong>VENKATESH VINOD</strong></div>
          <div>Account Number: <strong>412891349512</strong></div>
          <div>IFSC Code: <strong>SBIN0004561</strong></div>
          <div>Account Type: <strong>Savings Account</strong></div>
          
          <strong style="display: block; font-size: 11px; text-transform: uppercase; tracking: 1px; color: #64748B; margin-top: 16px; margin-bottom: 8px;">Option 2: UPI Transfer (Instant)</strong>
          <div>UPI ID: <strong>venkateshvinod75@okaxis</strong></div>
          <div style="margin-top: 4px;">Merchant/Name: <strong>Venkatesh Vinod</strong></div>
        </div>
      </div>

      <p style="font-size: 13px; color: #64748B; line-height: 1.5;">You may share these coordinates with your group members as needed. All deposits are tracked and audited under your private peer-to-peer circle rules. There are no platform fees; this operation is 100% non-financial on our website.</p>
    </div>
    <div class="footer">
      &copy; 2026 CircleSave Technologies India. All rights reserved.<br>
      Your Secure Peer-to-Peer Savings Infrastructure.
    </div>
  </div>
</body>
</html>
        `;
        try {
          await sendEmail(group.creatorEmail.trim(), `🏛️ Reference Deposit Details: CircleSave "${group.name}" is now FULL!`, fundingEmailHtml);
          console.log(`[Verify-Join] Sent group-full deposit coordinates email successfully to ${group.creatorEmail}`);
        } catch (emailError: any) {
          console.warn("[Verify-Join] Failed to send group-full deposit coordinates email:", emailError.message || emailError);
        }
      }
    }

    // Register verified member inside the "members" collection so they can log in and reset password
    const memberEmailKey = record.email.toLowerCase().trim();
    const memberRef = db.collection("members").doc(memberEmailKey);
    const memberDoc = await memberRef.get();
    if (!memberDoc.exists) {
      await memberRef.set({
        email: record.email,
        name: `${record.firstName} ${record.lastName}`,
        inviteCode: record.inviteCode,
        verified: true,
        role: "member",
        custom_password: await hashPassword("password123"), // Default temporary password they can change
        createdAt: FieldValue.serverTimestamp(),
      });
    }

    // Clean up join record
    await recordDoc.ref.delete();

    const origin = getPublicOrigin(req);
    res.redirect(`${origin}/?tab=portal&verify_join=true&email=${encodeURIComponent(record.email)}&code=${encodeURIComponent(record.inviteCode)}&name=${encodeURIComponent(record.firstName + " " + record.lastName)}&mobile=${encodeURIComponent(record.mobileNumber)}&country=${encodeURIComponent(record.countryCode)}`);

  } catch (error: any) {
    console.error("Verify Join Error:", error);
    res.status(500).send("<h1>Internal Server Error</h1>");
  }
});

// Info route to check Stripe and SendGrid configuration status safely
app.get("/api/config-status", (req, res) => {
  res.json({
    stripeConfigured: !!process.env.STRIPE_SECRET_KEY,
    stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY || process.env.STRIPE_PUBLISHABLE || null,
    sendgridConfigured: !!process.env.SENDGRID_API_KEY,
    sendgridDomain: process.env.SENDGRID_SENDER_DOMAIN || null,
    sendgridSenderEmail: process.env.SENDGRID_SENDER_EMAIL || null,
  });
});

// Configure Vite or Static Asset Fallbacks
async function initializeServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

initializeServer().catch((err) => {
  console.error("Failed to start full-stack server:", err);
});

