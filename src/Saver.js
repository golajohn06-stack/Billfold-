const fs = require('fs');
const path = process.env.DB_PATH || './data.json';
function loadData() {
  try {
    if (!fs.existsSync(path)) return { users: [], subscriptions: [] };
    return JSON.parse(fs.readFileSync(path, 'utf8'));
  } catch (e) {
    return { users: [], subscriptions: [] };
  }
}
function saveData(data) {
  fs.writeFileSync(path, JSON.stringify(data, null, 2));
}
module.exports = { loadData, saveData };
