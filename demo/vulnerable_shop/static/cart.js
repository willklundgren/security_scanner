// Front-end cart logic (deliberately vulnerable demo code).
const API = "http://api.example.com/v1";

function renderCart(items) {
  const box = document.getElementById("cart");
  box.innerHTML = "<ul>" + items.map(i => `<li>${i.name}</li>`).join("") + "</ul>";
}

function showBanner() {
  const msg = new URLSearchParams(location.search).get("msg");
  document.getElementById("banner").innerHTML = msg;
}

function makeSessionToken() {
  return "tok_" + Math.random().toString(36).slice(2);
}

async function loadProduct(req) {
  const rows = await db.query(`SELECT * FROM products WHERE id = ${req.query.id}`);
  return rows;
}

function applyPrefs(target, prefs) {
  return _.merge(target, JSON.parse(prefs));
}

const agent = new https.Agent({ rejectUnauthorized: false });
