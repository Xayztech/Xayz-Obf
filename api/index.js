const express = require('express');
const cors = require('cors');
const JsConfuser = require('js-confuser');
const axios = require('axios');
const { getFileContent, saveFileContent } = require('./lib/github');
const { configs, addProtection, addkeras, addBypass, killBypass, BergemaSelamanya, addKode, addTools } = require('./lib/logic');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(cors());
app.use(express.static('public'));

const BOT_TOKEN = process.env.BOT_TOKEN;
const CHANNEL_ID = process.env.CHANNEL_ID;

app.post('/api/auth', async (req, res) => {
    const { id, first_name, username } = req.body;
    try {
        const url = `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${CHANNEL_ID}&user_id=${id}`;
        const response = await axios.get(url);
        const status = response.data.result.status;

        if (["creator", "administrator", "member", "restricted"].includes(status)) {
            const users = await getFileContent("data/users.json");
            if (!users.find(u => u.id === id)) {
                users.push({ id, username, first_name, joinedAt: new Date().toISOString() });
                await saveFileContent("data/users.json", users, "Add user " + id);
            }
            return res.json({ success: true, user: { id, username, first_name } });
        } else {
            return res.status(403).json({ success: false, message: "Belum Join Channel" });
        }
    } catch (error) {
        return res.status(500).json({ success: false, message: "Error Auth" });
    }
});

app.post('/api/encrypt', async (req, res) => {
    const { userId, code, method, params } = req.body;
    
    if (!configs[method]) return res.status(400).json({ error: "Method invalid" });

    try {
        let protectedCode = code;
        
        if (method === 'safecursed' || method === 'safesc') protectedCode = addProtection(protectedCode);
        if (method === 'absolut' || method === 'court') protectedCode = addBypass(protectedCode);
        if (method === 'rushcers') protectedCode = killBypass(protectedCode);
        if (method === 'oval') protectedCode = addProtection(protectedCode);
        if (method === 'olive') protectedCode = addTools(protectedCode);
        if (method === 'obfors') protectedCode = addkeras(protectedCode);
        if (method === 'zenc') protectedCode = addProtection(protectedCode);

        let config = configs[method]();
        
        if (method === 'custom' && params) config = configs['custom'](params);
        if (method === 'timelocked' && params) {
             const conf = configs['timelocked'](params);
             protectedCode = conf.preamble + protectedCode;
             delete conf.preamble;
             config = conf;
        }

        const obfuscated = await JsConfuser.obfuscate(protectedCode, config);
        const resultCode = obfuscated.code || obfuscated;

        const historyPath = `data/history/${userId}.json`;
        const history = await getFileContent(historyPath);
        
        history.push({
            method,
            timestamp: new Date().toISOString(),
            originalLength: code.length,
            encryptedLength: resultCode.length,
            resultCode: resultCode 
        });

        await saveFileContent(historyPath, history, `Update history ${userId}`);

        res.json({ success: true, code: resultCode });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/history/:userId', async (req, res) => {
    try {
        const history = await getFileContent(`data/history/${req.params.userId}.json`);
        res.json({ success: true, data: history });
    } catch (error) {
        res.json({ success: true, data: [] });
    }
});

app.listen(3000, () => console.log('Server Ready'));

module.exports = app;