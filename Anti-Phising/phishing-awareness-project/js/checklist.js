// =============================================
// DecodeLabs - Red Flag Checklist Logic
// =============================================

const RED_FLAGS = [
  // --- SENDER / DOMAIN ---
  {
    id: 'rf1', section: 'Sender & Domain Checks',
    title: 'Sender-Domain Mismatch',
    desc: 'The display name conflicts with the actual routing domain (e.g., "Microsoft Support" but sent from support@logins-updates.com).',
    weight: 15, icon: '📧'
  },
  {
    id: 'rf2', section: 'Sender & Domain Checks',
    title: 'Lookalike / Spoofed Domain',
    desc: 'Domain uses typosquatting (amaz0n.com), homoglyph attacks (Cyrillic characters), or combosquatting (yourcompany-secure-login.com).',
    weight: 20, icon: '🎭'
  },
  {
    id: 'rf3', section: 'Sender & Domain Checks',
    title: 'Free Email Provider as Corporate Sender',
    desc: 'A Gmail, Yahoo, or Hotmail address is used for what appears to be an official corporate communication.',
    weight: 15, icon: '📮'
  },
  {
    id: 'rf4', section: 'Sender & Domain Checks',
    title: 'Subdomain Trap',
    desc: 'The malicious root domain is buried at the end of a long, legitimate-looking string (e.g., www.decodelabs.tech.login-update.com). Read URLs right to left.',
    weight: 20, icon: '🕸️'
  },
  // --- CONTENT ---
  {
    id: 'rf5', section: 'Content & Language',
    title: 'Urgency / Time Pressure',
    desc: 'Artificial time pressure ("Account locked in 30 minutes") designed to trigger a fight-or-flight response and bypass rational processing.',
    weight: 15, icon: '⏱️'
  },
  {
    id: 'rf6', section: 'Content & Language',
    title: 'Authority Impersonation',
    desc: 'Impersonates C-suite (CEO, CFO), IT department, law enforcement, or a government agency to demand unquestioned compliance.',
    weight: 20, icon: '🏛️'
  },
  {
    id: 'rf7', section: 'Content & Language',
    title: 'Urgent Bypass Requests',
    desc: 'Demands for secrecy or explicit instructions to bypass normal procurement or security procedures ("Do not discuss with anyone").',
    weight: 25, icon: '🚫'
  },
  {
    id: 'rf8', section: 'Content & Language',
    title: 'Requests for Sensitive Info',
    desc: 'Unexpected prompts for MFA codes, passwords, SSN, payment details, or credential changes sent over email.',
    weight: 25, icon: '🔑'
  },
  // --- LINKS & ATTACHMENTS ---
  {
    id: 'rf9', section: 'Links & Attachments',
    title: 'Suspicious / Shortened URL',
    desc: 'Links use URL shorteners (bit.ly, tinyurl) to hide the true destination, or point to an IP address instead of a named domain.',
    weight: 20, icon: '🔗'
  },
  {
    id: 'rf10', section: 'Links & Attachments',
    title: 'Dangerous File Attachment',
    desc: 'Uncommon or dangerous file extensions (.exe, .js, .iso, .scr, .hta, .lnk) or HTML smuggling links posing as standard documents.',
    weight: 30, icon: '📎'
  },
  // --- MODERN VECTORS ---
  {
    id: 'rf11', section: 'Modern Attack Vectors',
    title: 'QR Code Prompt (Quishing)',
    desc: 'Unsolicited QR codes demanding a scan to secure your account — bypasses desktop URL filters entirely by forcing mobile device use.',
    weight: 20, icon: '⬛'
  },
  {
    id: 'rf12', section: 'Modern Attack Vectors',
    title: 'Security Callback Scam (TOAD)',
    desc: 'Email contains no malicious links, only a phone number urging the user to call "Support" to resolve a fake charge or subscription.',
    weight: 15, icon: '📞'
  },
  {
    id: 'rf13', section: 'Modern Attack Vectors',
    title: 'MFA Fatigue Attack',
    desc: 'Multiple, unprompted authenticator push notifications designed to wear the user down until they accidentally or frustratedly hit "Approve".',
    weight: 25, icon: '📲'
  },
  {
    id: 'rf14', section: 'Modern Attack Vectors',
    title: 'Fake Forwarded Email Chain',
    desc: 'FW: threads containing pasted headers and odd timestamps of conversations the user was never actually part of.',
    weight: 15, icon: '↩️'
  },
];

function buildChecklist() {
  const container = document.getElementById('checklist-container');
  if (!container) return;

  const sections = [...new Set(RED_FLAGS.map(f => f.section))];

  sections.forEach(section => {
    const sectionDiv = document.createElement('div');
    sectionDiv.className = 'checklist-section';

    sectionDiv.innerHTML = `<div class="checklist-section-title">📂 ${section}</div>`;

    RED_FLAGS.filter(f => f.section === section).forEach(flag => {
      const item = document.createElement('div');
      item.className = 'checklist-item';
      item.id = `item-${flag.id}`;
      item.innerHTML = `
        <input type="checkbox" id="${flag.id}" data-weight="${flag.weight}"/>
        <div>
          <label for="${flag.id}">${flag.icon} ${flag.title} <span class="tag tag-red" style="font-size:0.7rem;">+${flag.weight} pts</span></label>
          <div class="desc">${flag.desc}</div>
        </div>
      `;

      const cb = item.querySelector('input[type="checkbox"]');
      cb.addEventListener('change', () => {
        item.classList.toggle('checked', cb.checked);
        updateScore();
      });

      sectionDiv.appendChild(item);
    });

    container.appendChild(sectionDiv);
  });
}

function updateScore() {
  let total = 0;
  let checked = 0;
  document.querySelectorAll('#checklist-container input[type="checkbox"]').forEach(cb => {
    if (cb.checked) {
      total += parseInt(cb.dataset.weight);
      checked++;
    }
  });

  total = Math.min(total, 100);

  document.getElementById('score-display').textContent = total;
  document.getElementById('flags-count').textContent = checked;

  const bar = document.getElementById('checklist-bar');
  bar.style.width = total + '%';
  bar.className = 'score-bar-fill ' + (total >= 50 ? 'fill-danger' : total >= 20 ? 'fill-suspicious' : 'fill-safe');

  // Update verdict
  const verdictBox = document.getElementById('verdict-box');
  const verdictText = document.getElementById('verdict-text');
  const verdictAction = document.getElementById('verdict-action');

  if (checked === 0) {
    verdictBox.className = 'result-box';
    return;
  }

  verdictBox.className = 'result-box show ' + (total >= 50 ? 'result-danger' : total >= 20 ? 'result-suspicious' : 'result-safe');

  if (total >= 50) {
    verdictText.innerHTML = '🚨 MALICIOUS — Block & Escalate';
    verdictAction.innerHTML = `<strong>Action:</strong> Do not click any links or open any attachments. Report immediately to the security team using the internal reporting plugin. Block the sender domain. Escalate for full investigation.`;
  } else if (total >= 20) {
    verdictText.innerHTML = '⚠️ SUSPICIOUS — Warn User';
    verdictAction.innerHTML = `<strong>Action:</strong> Treat with caution. Verify through an out-of-band channel (phone call to a known number). Do not act on any requests until confirmed. Report to IT security.`;
  } else {
    verdictText.innerHTML = '✅ LIKELY SAFE — Close';
    verdictAction.innerHTML = `<strong>Action:</strong> Low risk indicators. No immediate action required. Stay alert and apply the Pause, Verify, Report rule for any future requests from this sender.`;
  }
}

function resetChecklist() {
  document.querySelectorAll('#checklist-container input[type="checkbox"]').forEach(cb => {
    cb.checked = false;
    document.getElementById(`item-${cb.id}`)?.classList.remove('checked');
  });
  updateScore();
}

document.addEventListener('DOMContentLoaded', () => {
  buildChecklist();

  const resetBtn = document.getElementById('reset-btn');
  if (resetBtn) resetBtn.addEventListener('click', resetChecklist);
});
