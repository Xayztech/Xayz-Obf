const { Octokit } = require("@octokit/rest");
const crypto = require("crypto");

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const REPO_OWNER = process.env.REPO_OWNER;
const REPO_NAME = process.env.REPO_NAME;
const ENCRYPTION_KEY = crypto.scryptSync(process.env.STORAGE_SECRET || 'xycoolcraft-secret', 'salt', 32);
const IV_LENGTH = 16;

const octokit = new Octokit({ auth: GITHUB_TOKEN });

function encryptData(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decryptData(text) {
    if (!text) return null;
    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) {
        return "[]";
    }
}

async function getFileContent(path) {
    try {
        const { data } = await octokit.repos.getContent({
            owner: REPO_OWNER,
            repo: REPO_NAME,
            path: path,
        });
        const content = Buffer.from(data.content, 'base64').toString('utf-8');
        return JSON.parse(decryptData(content) || "[]");
    } catch (error) {
        if (error.status === 404) return [];
        throw error;
    }
}

async function saveFileContent(path, contentData, message) {
    let sha;
    try {
        const { data } = await octokit.repos.getContent({
            owner: REPO_OWNER,
            repo: REPO_NAME,
            path: path,
        });
        sha = data.sha;
    } catch (error) {}

    const encryptedContent = encryptData(JSON.stringify(contentData));
    const base64Content = Buffer.from(encryptedContent).toString('base64');

    await octokit.repos.createOrUpdateFileContents({
        owner: REPO_OWNER,
        repo: REPO_NAME,
        path: path,
        message: message,
        content: base64Content,
        sha: sha
    });
}

module.exports = { getFileContent, saveFileContent };