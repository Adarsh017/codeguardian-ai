// Deliberately vulnerable front-end code for CodeGuardian AI testing
var apiBase = "http://api.insecure-demo.com";
const apiKey = "AIzaSyD-demoKeyForTesting1234567890abcde";

function renderComment(comment) {
  document.getElementById("comments").innerHTML = comment.text;
}

function sessionToken() {
  const sessionToken = Math.random().toString(36).substring(2);
  return sessionToken;
}

function calculate(expression) {
  return eval(expression);
}

async function loadUsers(ids) {
  const users = [];
  for (const id of ids) {
    const res = await fetch(apiBase + "/users/" + id);
    users.push(await res.json());
  }
  if (users.length == 0) {
    console.log("no users");
  }
  return users;
}

function findOrders(db, userId) {
  return db.query("SELECT * FROM orders WHERE user_id = " + userId + "");
}
