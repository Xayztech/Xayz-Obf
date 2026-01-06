let currentUser = null;

// --- TELEGRAM LOGIN ---
function onTelegramAuth(user) {
    document.getElementById('login-status').innerText = "CONNECTING TO SERVER...";
    fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(user)
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            currentUser = data.user;
            localStorage.setItem('xy_user', JSON.stringify(currentUser));
            showDashboard();
        } else {
            alert("ACCESS DENIED: " + data.message);
            if(data.message.includes("Join")) window.location.href = "https://t.me/XayTeam"; // GANTI LINK CHANNEL
        }
    })
    .catch(() => alert("SERVER ERROR"));
}

// --- GUEST MODE ---
function enterGuestMode() {
    currentUser = {
        id: "guest",
        username: "Guest",
        first_name: "Guest Mode (No History)"
    };
    // Jangan simpan di localStorage agar tidak auto-login sebagai guest nanti
    showDashboard();
    
    // Sembunyikan tab history untuk Guest
    document.getElementById('history-menu-item').style.display = 'none';
}

// --- TUTORIAL MODAL ---
function openTutorial() {
    document.getElementById('tutorial-modal').classList.remove('hidden');
}

function closeTutorial() {
    document.getElementById('tutorial-modal').classList.add('hidden');
}

// --- INIT ---
window.onload = () => {
    const saved = localStorage.getItem('xy_user');
    if (saved) {
        currentUser = JSON.parse(saved);
        showDashboard();
    }
    const sel = document.getElementById('methodSelect');
    sel.onchange = () => {
        const val = sel.value;
        const div = document.getElementById('paramInputDiv');
        const inp = document.getElementById('paramInput');
        div.classList.add('hidden');
        if(val === 'custom') { div.classList.remove('hidden'); inp.placeholder = "Enter Custom Name"; }
        if(val === 'timelocked') { div.classList.remove('hidden'); inp.placeholder = "Enter Days (e.g. 30)"; }
    };
};

function showDashboard() {
    document.getElementById('login-section').classList.add('hidden');
    document.getElementById('dashboard-section').classList.remove('hidden');
    document.getElementById('user-display').innerText = currentUser.first_name;
    
    if(currentUser.id !== 'guest') {
        loadHistory();
    }
}

function logout() {
    localStorage.removeItem('xy_user');
    location.reload();
}

function switchTab(tab) {
    // Cegah guest buka history
    if(tab === 'history' && currentUser.id === 'guest') {
        alert("Guest cannot access history!");
        return;
    }

    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.sidebar li').forEach(el => el.classList.remove('active'));
    document.getElementById(`${tab}-tab`).classList.remove('hidden');
    event.currentTarget.classList.add('active');
    
    if (tab === 'history') loadHistory();
}

// --- FILE HANDLING ---
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('fileInput');
let currentCode = "";
let fileName = "";

dropZone.onclick = () => fileInput.click();
fileInput.onchange = (e) => {
    const file = e.target.files[0];
    if(!file) return;
    fileName = file.name;
    const reader = new FileReader();
    reader.onload = (ev) => {
        currentCode = ev.target.result;
        dropZone.innerHTML = `<i class="fas fa-check-circle" style="color:#0f0"></i><h3>${file.name}</h3><p>READY</p>`;
    };
    reader.readAsText(file);
};

// --- PROCESS ---
async function processEncryption() {
    if (!currentCode) return alert("NO FILE DETECTED");
    
    const method = document.getElementById('methodSelect').value;
    const param = document.getElementById('paramInput').value;
    const btn = document.querySelector('.cyber-btn');
    
    btn.innerHTML = "ENCRYPTING... <i class='fas fa-cog fa-spin'></i>";
    btn.disabled = true;

    try {
        const res = await fetch('/api/encrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                userId: currentUser.id,
                code: currentCode,
                method: method,
                params: param
            })
        });

        const data = await res.json();
        if (data.success) {
            document.getElementById('result-area').classList.remove('hidden');
            document.getElementById('codeResult').value = data.code;
        } else {
            alert("ERROR: " + data.error);
        }
    } catch {
        alert("SERVER CONNECTION LOST");
    } finally {
        btn.innerHTML = "EXECUTE PROTOCOL";
        btn.disabled = false;
    }
}

function downloadResult() {
    const code = document.getElementById('codeResult').value;
    const blob = new Blob([code], { type: 'text/javascript' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ENC-${fileName}`;
    a.click();
}

async function loadHistory() {
    if (!currentUser || currentUser.id === 'guest') return;
    const container = document.getElementById('history-container');
    container.innerHTML = "LOADING DATABASE...";
    try {
        const res = await fetch(`/api/history/${currentUser.id}`);
        const data = await res.json();
        container.innerHTML = "";
        if(data.data.length === 0) container.innerHTML = "NO LOGS FOUND";
        data.data.reverse().forEach(item => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.innerHTML = `
                <div>
                    <strong style="color:var(--neon-blue)">${item.method.toUpperCase()}</strong><br>
                    <small>${item.timestamp}</small>
                </div>
                <button class="download-btn" onclick="downloadString('${encodeURIComponent(item.resultCode)}', 'HIST-${item.method}.js')">
                    <i class="fas fa-download"></i>
                </button>
            `;
            container.appendChild(div);
        });
    } catch {
        container.innerHTML = "DB ERROR";
    }
}

function downloadString(enc, fname) {
    const code = decodeURIComponent(enc);
    const blob = new Blob([code], { type: 'text/javascript' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = fname;
    a.click();
        }
