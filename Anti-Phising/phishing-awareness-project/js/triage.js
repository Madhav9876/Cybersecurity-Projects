// =============================================
// DecodeLabs - Phishing Triage Decision Tree
// =============================================

const TRIAGE_STEPS = [
  {
    id: 'start',
    question: 'Does the sender\'s display name match the actual email address domain?',
    hint: 'Expand the "From:" field. E.g., "CEO Name" but sent from hacker@gmail.com = mismatch.',
    type: 'yesno',
    yes: 'q_links',       // mismatch = suspicious
    no: 'q_links',        // match = continue checking
    yesLabel: 'No — they do NOT match (mismatch detected)',
    noLabel: 'Yes — they match',
    yesFlag: { text: 'Sender-Domain Mismatch detected', severity: 'high' },
  },
  {
    id: 'q_links',
    question: 'Do any links in the message point to a suspicious or unfamiliar domain?',
    hint: 'Hover over links without clicking. Read URLs right to left to find the true root domain. Watch for typosquatting (amaz0n.com) and subdomain traps.',
    type: 'yesno',
    yes: 'q_urgency',
    no: 'q_urgency',
    yesLabel: 'Yes — links look suspicious or don\'t match the sender',
    noLabel: 'No — links appear legitimate or there are no links',
    yesFlag: { text: 'Suspicious URL(s) detected', severity: 'high' },
  },
  {
    id: 'q_urgency',
    question: 'Does the message use urgency, fear, or threats to pressure you into acting quickly?',
    hint: 'Look for phrases like "account locked in 30 minutes", "immediate action required", "legal consequences", or "last warning".',
    type: 'yesno',
    yes: 'q_sensitive',
    no: 'q_sensitive',
    yesLabel: 'Yes — creates pressure, urgency, or fear',
    noLabel: 'No — neutral, no time pressure',
    yesFlag: { text: 'Urgency / cognitive trigger tactic detected', severity: 'medium' },
  },
  {
    id: 'q_sensitive',
    question: 'Does the message ask for sensitive information (passwords, MFA codes, bank details, SSN)?',
    hint: 'Legitimate organizations never request credentials, OTP codes, or financial details via email.',
    type: 'yesno',
    yes: 'q_bypass',
    no: 'q_bypass',
    yesLabel: 'Yes — requests sensitive information',
    noLabel: 'No — no sensitive info requested',
    yesFlag: { text: 'Sensitive information request', severity: 'high' },
  },
  {
    id: 'q_bypass',
    question: 'Does the message ask you to keep it secret, bypass normal procedures, or avoid telling colleagues?',
    hint: 'Phrases like "Do not discuss with anyone", "bypass standard procedure", or "strictly confidential" are major red flags — especially combined with financial requests.',
    type: 'yesno',
    yes: 'q_attachment',
    no: 'q_attachment',
    yesLabel: 'Yes — demands secrecy or procedure bypass',
    noLabel: 'No — no such demands',
    yesFlag: { text: 'Secrecy / procedure bypass demand', severity: 'high' },
  },
  {
    id: 'q_attachment',
    question: 'Does the message contain an unexpected attachment?',
    hint: 'Be especially cautious of .exe, .js, .iso, .scr, .hta, .lnk files. Even a PDF or .zip can contain malicious payloads. Were you expecting this file?',
    type: 'yesno',
    yes: 'q_expected',
    no: 'q_context',
    yesLabel: 'Yes — there is an attachment',
    noLabel: 'No — no attachment',
    yesFlag: null,
  },
  {
    id: 'q_expected',
    question: 'Were you expecting this attachment from this sender?',
    hint: 'Did you initiate this request? Is the sender someone you work with regularly? Did you ask for this file?',
    type: 'yesno',
    yes: 'q_context',
    no: 'q_context',
    yesLabel: 'No — it was unexpected / unsolicited',
    noLabel: 'Yes — I was expecting this',
    yesFlag: { text: 'Unexpected / unsolicited attachment', severity: 'high' },
  },
  {
    id: 'q_context',
    question: 'Does the context of this message make sense — is it something you\'d normally receive?',
    hint: 'E.g., A CEO requesting a wire transfer by email without a prior conversation, an IT password reset you didn\'t request, an HR form with a strict deadline.',
    type: 'yesno',
    yes: 'verdict',
    no: 'verdict',
    yesLabel: 'No — the context is unusual or unexpected',
    noLabel: 'Yes — the context seems normal',
    yesFlag: { text: 'Unusual / unexpected contextual request', severity: 'medium' },
  },
];

const VERDICT_THRESHOLDS = {
  malicious: 3,   // 3+ high-severity flags
  suspicious: 1,  // 1+ any flag
};

let currentStep = 0;
let flags = [];
let stepHistory = [];

function getStepById(id) {
  return TRIAGE_STEPS.find(s => s.id === id);
}

function renderStep(stepId) {
  const step = getStepById(stepId);
  if (!stepId || stepId === 'verdict') {
    renderVerdict();
    return;
  }

  const container = document.getElementById('triage-container');
  const progress = stepHistory.length;
  const total = TRIAGE_STEPS.length;
  const pct = Math.round((progress / total) * 100);

  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('progress-label').textContent = `Step ${progress + 1} of ${total}`;

  container.innerHTML = `
    <div class="card tree-step active">
      <div style="margin-bottom:1rem;">
        <span class="tag tag-blue">Step ${progress + 1} / ${total}</span>
        ${flags.length > 0 ? `<span class="tag tag-red" style="margin-left:6px;">${flags.length} flag${flags.length > 1 ? 's' : ''} found</span>` : ''}
      </div>
      <div class="tree-question">${step.question}</div>
      <div class="tree-hint">💡 ${step.hint}</div>
      <div class="tree-options">
        <button class="tree-opt-btn tree-opt-yes" onclick="handleAnswer('${stepId}', true)">${step.yesLabel}</button>
        <button class="tree-opt-btn tree-opt-no" onclick="handleAnswer('${stepId}', false)">${step.noLabel}</button>
      </div>
      ${progress > 0 ? `<button onclick="goBack()" style="margin-top:1.5rem; background:none; border:none; color:var(--muted); cursor:pointer; font-size:0.88rem;">← Back</button>` : ''}
    </div>
  `;
}

function handleAnswer(stepId, isYes) {
  const step = getStepById(stepId);
  stepHistory.push({ stepId, isYes });

  if (isYes && step.yesFlag) {
    flags.push(step.yesFlag);
  }

  const nextId = isYes ? step.yes : step.no;
  renderStep(nextId);
}

function goBack() {
  if (stepHistory.length === 0) return;
  const last = stepHistory.pop();

  // Remove flag added by this step if any
  const step = getStepById(last.stepId);
  if (last.isYes && step.yesFlag) {
    flags = flags.filter(f => f.text !== step.yesFlag.text);
  }

  renderStep(last.stepId);
}

function renderVerdict() {
  const highFlags = flags.filter(f => f.severity === 'high');
  const container = document.getElementById('triage-container');

  document.getElementById('progress-fill').style.width = '100%';
  document.getElementById('progress-label').textContent = 'Triage Complete';

  let verdictClass, icon, title, action, actionClass;

  if (highFlags.length >= 2 || flags.length >= 4) {
    verdictClass = 'verdict-malicious';
    icon = '🚨';
    title = 'MALICIOUS';
    action = `<strong>Action: Block Domain &amp; Escalate</strong><br/>Do NOT interact with this message further. Report immediately using your internal security reporting plugin. The security team must purge this threat from all inboxes. Block the sender domain at the email gateway.`;
    actionClass = 'text-danger';
  } else if (flags.length >= 1) {
    verdictClass = 'verdict-suspicious';
    icon = '⚠️';
    title = 'SUSPICIOUS';
    action = `<strong>Action: Warn User &amp; Verify</strong><br/>Do not act on any requests in this message. Verify the sender through an out-of-band channel — if it came by email, call a known directory number to confirm. Report to IT security.`;
    actionClass = 'text-warning';
  } else {
    verdictClass = 'verdict-safe';
    icon = '✅';
    title = 'LIKELY SAFE';
    action = `<strong>Action: Close</strong><br/>No phishing indicators were identified. You may proceed. Remember to stay vigilant — apply Pause, Verify, Report for any sensitive or unexpected requests.`;
    actionClass = 'text-success';
  }

  const flagsHtml = flags.length > 0
    ? `<div style="text-align:left; margin-top:1.2rem; max-width:500px; margin-left:auto; margin-right:auto;">
        <strong style="display:block; margin-bottom:0.6rem;">Flags identified during triage:</strong>
        <ul style="list-style:none; display:grid; gap:6px;">
          ${flags.map(f => `
            <li style="padding:8px 12px; border-radius:6px; background:${f.severity === 'high' ? '#ffebee' : '#fff3e0'}; font-size:0.88rem; display:flex; align-items:center; gap:8px;">
              ${f.severity === 'high' ? '🔴' : '🟠'} ${f.text}
            </li>`).join('')}
        </ul>
      </div>`
    : `<p style="color:var(--muted); margin-top:1rem;">No red flags were detected during this triage session.</p>`;

  container.innerHTML = `
    <div class="tree-verdict ${verdictClass}">
      <div class="verdict-icon">${icon}</div>
      <div class="verdict-title ${actionClass}">${title}</div>
      <div class="verdict-action">${action}</div>
      ${flagsHtml}
      <div style="margin-top:1.8rem; display:flex; gap:10px; justify-content:center; flex-wrap:wrap;">
        <button class="btn btn-primary" onclick="restartTriage()">🔄 Triage Another Email</button>
        <a href="checklist.html" class="btn btn-outline" style="background:var(--primary); color:#fff;">✅ Open Red Flag Checklist</a>
      </div>
    </div>
  `;
}

function restartTriage() {
  flags = [];
  stepHistory = [];
  document.getElementById('progress-fill').style.width = '0%';
  document.getElementById('progress-label').textContent = `Step 1 of ${TRIAGE_STEPS.length}`;
  renderStep('start');
}

document.addEventListener('DOMContentLoaded', () => {
  renderStep('start');
});
