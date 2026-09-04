// =============================================
// DecodeLabs - Phishing Email Analyzer
// =============================================

const PHISHING_KEYWORDS = [
  { word: /\burgent\b/i, score: 10, label: "Urgency keyword" },
  { word: /\bimmediately\b/i, score: 10, label: "Urgency keyword" },
  { word: /\bverify\s+your\s+(account|identity|email|password)/i, score: 15, label: "Credential harvesting prompt" },
  { word: /\bclick\s+here\b/i, score: 8, label: "Generic CTA link" },
  { word: /\baccount\s+(suspended|locked|disabled|blocked)/i, score: 20, label: "Account threat" },
  { word: /\bpassword\s+(expired|reset|change)/i, score: 15, label: "Password manipulation" },
  { word: /\bconfirm\s+(your\s+)?(account|identity|details|information)/i, score: 12, label: "Identity confirmation request" },
  { word: /\bunusual\s+(activity|sign.?in|login|access)/i, score: 15, label: "Fake security alert" },
  { word: /\bwire\s+transfer\b/i, score: 25, label: "Wire transfer request (BEC)" },
  { word: /\bdo\s+not\s+(share|tell|discuss)\b/i, score: 20, label: "Secrecy demand" },
  { word: /\bbypass\s+(standard|normal|usual)\b/i, score: 25, label: "Procedure bypass request" },
  { word: /\bstrictly\s+confidential\b/i, score: 15, label: "Artificial confidentiality" },
  { word: /\b(free\s+gift|you\s+won|you\s+have\s+been\s+selected|prize)\b/i, score: 20, label: "Fear/Greed lure" },
  { word: /\b(legal\s+action|law\s+enforcement|arrest|penalty|fine)\b/i, score: 20, label: "Fear/threat tactic" },
  { word: /\b(update\s+your\s+billing|payment\s+(failed|failure|declined))\b/i, score: 15, label: "Payment urgency lure" },
  { word: /\bMFA\s+(code|token|one.?time)\b/i, score: 20, label: "MFA code request" },
  { word: /\b(ssn|social\s+security|bank\s+account|credit\s+card)\b/i, score: 25, label: "PII harvesting" },
  { word: /\b(subscribe|subscription)\s+(expire|renew|cancel)/i, score: 12, label: "Subscription lure" },
  { word: /\bscan\s+(this\s+)?QR\b/i, score: 15, label: "QR code prompt (Quishing)" },
  { word: /\bcall\s+1[-\s]?800\b/i, score: 15, label: "Callback phishing (TOAD)" },
  { word: /\b(lost|forgot).{0,20}(wallet|passport|phone)\b/i, score: 20, label: "BEC lost item scenario" },
];

const SUSPICIOUS_DOMAINS = [
  /amaz[o0]n/i, /payp[a@]l/i, /g[o0]{2}gle/i, /micros[o0]ft/i,
  /app1e/i, /linkedln/i, /faceb[o0]{2}k/i, /netfl[i1]x/i,
  /\.tk$/, /\.ml$/, /\.cf$/, /\.ga$/, /\.gq$/,
  /login[-.]update/i, /secure[-.]login/i, /account[-.]verify/i,
  /support[-.]ticket/i, /helpdesk[-.]portal/i,
];

const SUSPICIOUS_TLDS = ['.tk', '.ml', '.cf', '.ga', '.gq', '.xyz', '.top', '.click', '.work', '.link'];

const URL_REGEX = /https?:\/\/[^\s"'<>]+/gi;
const EMAIL_REGEX = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/gi;

function analyzeText(rawText) {
  const findings = [];
  let score = 0;

  // --- 1. Keyword analysis ---
  PHISHING_KEYWORDS.forEach(({ word, score: s, label }) => {
    const matches = rawText.match(word);
    if (matches) {
      score += s;
      findings.push({ type: 'keyword', severity: s >= 20 ? 'high' : s >= 12 ? 'medium' : 'low', label, match: matches[0] });
    }
  });

  // --- 2. URL analysis ---
  const urls = rawText.match(URL_REGEX) || [];
  urls.forEach(url => {
    let urlScore = 0;
    const flags = [];

    // Suspicious TLDs
    SUSPICIOUS_TLDS.forEach(tld => {
      if (url.toLowerCase().includes(tld)) {
        urlScore += 20; flags.push(`Suspicious TLD: ${tld}`);
      }
    });

    // Domain lookalike patterns
    SUSPICIOUS_DOMAINS.forEach(pattern => {
      if (pattern.test(url)) {
        urlScore += 25; flags.push('Lookalike / spoofed domain pattern');
      }
    });

    // Subdomain trap (many dots before root domain)
    const domainPart = url.replace(/https?:\/\//, '').split('/')[0];
    const dotCount = (domainPart.match(/\./g) || []).length;
    if (dotCount >= 3) {
      urlScore += 20; flags.push('Subdomain trap — read URL right to left');
    }

    // URL shorteners
    if (/bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|rb\.gy|is\.gd/i.test(url)) {
      urlScore += 15; flags.push('URL shortener — hides true destination');
    }

    // HTTP (not HTTPS)
    if (url.startsWith('http://')) {
      urlScore += 10; flags.push('Non-HTTPS link');
    }

    // IP address instead of domain
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(url)) {
      urlScore += 30; flags.push('IP address used instead of domain');
    }

    if (urlScore > 0) {
      score += urlScore;
      findings.push({
        type: 'url',
        severity: urlScore >= 30 ? 'high' : urlScore >= 15 ? 'medium' : 'low',
        label: `Suspicious URL: ${url.length > 60 ? url.substring(0, 60) + '…' : url}`,
        match: flags.join('; ')
      });
    }
  });

  // --- 3. Email header analysis ---
  const emails = rawText.match(EMAIL_REGEX) || [];
  emails.forEach(email => {
    const domain = email.split('@')[1]?.toLowerCase() || '';

    // Free email used as sender for corporate communication
    if (/gmail\.com|yahoo\.com|hotmail\.com|outlook\.com/.test(domain)) {
      score += 15;
      findings.push({ type: 'header', severity: 'medium', label: 'Free email provider as sender', match: email });
    }

    // Check for combosquatting
    SUSPICIOUS_DOMAINS.forEach(pattern => {
      if (pattern.test(domain)) {
        score += 25;
        findings.push({ type: 'header', severity: 'high', label: 'Lookalike sender domain', match: email });
      }
    });
  });

  // --- 4. Attachment red flags ---
  if (/\.(exe|js|vbs|bat|cmd|scr|iso|lnk|hta|ps1)\b/i.test(rawText)) {
    score += 30;
    findings.push({ type: 'attachment', severity: 'high', label: 'Dangerous file extension found', match: rawText.match(/\.(exe|js|vbs|bat|cmd|scr|iso|lnk|hta|ps1)\b/i)[0] });
  }

  if (/\.html?$/i.test(rawText) && /attachment/i.test(rawText)) {
    score += 20;
    findings.push({ type: 'attachment', severity: 'high', label: 'HTML attachment — potential HTML smuggling', match: 'HTML file attached' });
  }

  // --- 5. Determine verdict ---
  let verdict, severityClass, icon;
  if (score >= 50) {
    verdict = 'MALICIOUS';
    severityClass = 'result-danger';
    icon = '🚨';
  } else if (score >= 20) {
    verdict = 'SUSPICIOUS';
    severityClass = 'result-suspicious';
    icon = '⚠️';
  } else {
    verdict = 'LIKELY SAFE';
    severityClass = 'result-safe';
    icon = '✅';
  }

  return { score: Math.min(score, 100), findings, verdict, severityClass, icon };
}

function renderResults(result) {
  const { score, findings, verdict, severityClass, icon } = result;
  const box = document.getElementById('result-box');
  const bar = document.getElementById('score-bar');
  const scoreNum = document.getElementById('score-num');
  const findingsList = document.getElementById('findings-list');
  const verdictTitle = document.getElementById('verdict-title');

  // Score bar
  const pct = Math.min(score, 100);
  bar.style.width = pct + '%';
  bar.className = 'score-bar-fill ' + (pct >= 50 ? 'fill-danger' : pct >= 20 ? 'fill-suspicious' : 'fill-safe');
  scoreNum.textContent = pct;

  // Verdict
  box.className = 'result-box show ' + severityClass;
  verdictTitle.innerHTML = `${icon} ${verdict} <span style="font-size:0.85rem; font-weight:400;">(Risk Score: ${pct}/100)</span>`;

  // Findings
  findingsList.innerHTML = '';
  if (findings.length === 0) {
    findingsList.innerHTML = '<li class="flag-item"><span class="flag-icon">✅</span><div class="flag-content"><h4>No indicators detected</h4><p>No known phishing patterns were found. Always verify through an out-of-band channel for critical requests.</p></div></li>';
  } else {
    findings.forEach(f => {
      const severityColors = { high: '#c62828', medium: '#e65100', low: '#f57f17' };
      const icons = { keyword: '🔤', url: '🔗', header: '📧', attachment: '📎' };
      const li = document.createElement('li');
      li.className = 'flag-item found';
      li.innerHTML = `
        <span class="flag-icon">${icons[f.type] || '⚠️'}</span>
        <div class="flag-content">
          <h4 style="color:${severityColors[f.severity]}">[${f.severity.toUpperCase()}] ${f.label}</h4>
          <p>${f.match || ''}</p>
        </div>
      `;
      findingsList.appendChild(li);
    });
  }

  box.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ---- DOM wiring ----
document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('analyze-btn');
  const clearBtn = document.getElementById('clear-btn');
  const input = document.getElementById('email-input');

  if (btn) {
    btn.addEventListener('click', () => {
      const text = input.value.trim();
      if (!text) {
        alert('Please paste an email or message to analyze.');
        return;
      }
      const result = analyzeText(text);
      renderResults(result);
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      input.value = '';
      const box = document.getElementById('result-box');
      box.className = 'result-box';
      document.getElementById('score-bar').style.width = '0%';
      document.getElementById('score-num').textContent = '0';
      document.getElementById('findings-list').innerHTML = '';
    });
  }

  // Sample email loaders
  document.querySelectorAll('[data-sample]').forEach(btn => {
    btn.addEventListener('click', () => {
      input.value = SAMPLE_EMAILS[btn.dataset.sample] || '';
      input.focus();
    });
  });
});

const SAMPLE_EMAILS = {
  bec: `From: CEO - STRICTLY CONFIDENTIAL <ceo.urgent@executive-update.com>
To: finance@yourcompany.com
Subject: IMMEDIATE ACTION REQUIRED: Transfer Authorization

URGENT: Process the attached wire transfer instruction immediately.

This is critical and must remain STRICTLY CONFIDENTIAL.

Do not discuss with anyone.

Bypass standard procedure.

Transfer $45,000 to the following account before close of business today.

Account: 123456789
Bank: Offshore National

Thank you.`,

  mass: `From: Amazon Security <noreply@amaz0n-security-alerts.com>
To: you@email.com
Subject: Your account has been locked - Verify immediately

Dear Valued Customer,

We have detected unusual activity on your Amazon account. Your account has been suspended until you verify your identity.

Click here to verify your account: http://amaz0n-login-secure.tk/verify?user=you

You must complete this within 24 hours or your account will be permanently disabled.

Enter your password, credit card details, and SSN to proceed.

Amazon Security Team`,

  spear: `From: IT Security <it-support@yourcompany-helpdesk-portal.com>
To: employee@yourcompany.com
Subject: Mandatory: Password expires in 24 hrs

Hi Team,

Our records show your corporate password expires in 24 hours. Failure to reset will lock you out of all internal systems including Slack, Jira, and the VPN.

Reset your password immediately: https://bit.ly/secure-reset-3x9k

This is an automated security message. Do not reply to this email.

IT Security Department`,

  safe: `From: Sarah Lee <sarah.lee@company.com>
To: team@company.com
Subject: Q3 Project Status Update - Non-Urgent

Hi Team,

Please review the attached project status for Q3 at your earliest convenience.

No immediate action is required.

Thanks,
Sarah.

Attachment: Q3_Status.pdf`
};
