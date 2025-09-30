// static/js/chat.js
document.addEventListener("DOMContentLoaded", () => {
  const L = {
    en: {
      heroTitle: `GuideBot is ready to help you.
Type your question, choose your language, and get a quick, private answer.`,
      heroSub: `In moments of fear, panic or danger, the right info can save your life. GuideBot helps verify news and guide decisions.`,
      placeholder: "Write your question here...",
      send: "Send"
    },
    ar: {
      heroTitle: `البوت جاهز لمساعدتك.
اكتب سؤالك، اختر لغتك، وستصلك المعلومة فورًا.`,
      heroSub: `في لحظات الخوف أو التشتت، المعلومة الصحيحة قد تنقذك. بوت التحقق هنا لمساعدتك على تجنب الأخبار الكاذبة.`,
      placeholder: "اكتب سؤالك هنا...",
      send: "إرسال"
    }
  };

  let lang = "en";
  const btnEn = document.getElementById("lang-en");
  const btnAr = document.getElementById("lang-ar");
  const heroText = document.getElementById("hero-text");
  const heroSub = document.getElementById("hero-subtext");
  const userInput = document.getElementById("user-input");
  const sendBtn = document.getElementById("send-btn");
  const chatWindow = document.getElementById("chat-window");

  function setLanguage(l) {
    lang = l;
    btnEn.classList.toggle("active", l === "en");
    btnAr.classList.toggle("active", l === "ar");
    heroText.innerText = L[l].heroTitle;
    heroSub.innerText = L[l].heroSub;
    userInput.placeholder = L[l].placeholder;
    document.documentElement.dir = l === "ar" ? "rtl" : "ltr";
    chatWindow.dir = l === "ar" ? "rtl" : "ltr";
    sendBtn.innerText = L[l].send;
  }

  btnEn.addEventListener("click", () => setLanguage("en"));
  btnAr.addEventListener("click", () => setLanguage("ar"));
  setLanguage("en");

  // focus input on load
  userInput.focus();

  // append message
  function appendMessage(text, who = "bot") {
    const div = document.createElement("div");
    div.className = "message " + (who === "user" ? "user" : "bot");
    div.innerText = text;
    chatWindow.appendChild(div);
    chatWindow.scrollTop = chatWindow.scrollHeight;
    div.style.opacity = 0;
    setTimeout(() => (div.style.opacity = 1), 50); // fade-in
  }

  // thinking animation
  function showThinking() {
    const div = document.createElement("div");
    div.className = "message bot thinking";
    div.innerHTML = `<span class="dot"></span><span class="dot"></span><span class="dot"></span>`;
    chatWindow.appendChild(div);
    chatWindow.scrollTop = chatWindow.scrollHeight;
    return div;
  }

  async function sendMessage() {
    const txt = userInput.value.trim();
    if (!txt) return;
    appendMessage(txt, "user");
    userInput.value = "";

    const thinkingEl = showThinking();

    try {
      const res = await axios.post("/api/chat", { message: txt, lang: lang });
      thinkingEl.remove();

      if (res.data && res.data.reply) {
        appendMessage(res.data.reply, "bot");
      } else if (res.data && res.data.error) {
        appendMessage("⚠️ " + res.data.error, "bot");
      } else {
        appendMessage("⚠️ No reply", "bot");
      }
    } catch (err) {
      thinkingEl.remove();
      appendMessage("⚠️ Could not connect to server.", "bot");
      console.error(err);
    }
  }

  sendBtn.addEventListener("click", sendMessage);
  userInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
  });
});
