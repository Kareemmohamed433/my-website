// استيراد Firebase
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getAuth, signInWithPopup, GoogleAuthProvider } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";

// تهيئة Firebase باستخدام إعدادات مشروعك
const firebaseConfig = {
    apiKey: "YOUR_API_KEY",
    authDomain: "YOUR_PROJECT_ID.firebaseapp.com",
    projectId: "YOUR_PROJECT_ID",
    storageBucket: "YOUR_PROJECT_ID.appspot.com",
    messagingSenderId: "YOUR_SENDER_ID",
    appId: "YOUR_APP_ID"
};

// تهيئة التطبيق
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

// تهيئة تسجيل الدخول عبر Google
const provider = new GoogleAuthProvider();

// دالة تسجيل الدخول عبر Google
function googleSignIn() {
    signInWithPopup(auth, provider)
        .then((result) => {
            alert("✅ تم تسجيل الدخول بنجاح!");
            console.log(result.user);
        })
        .catch((error) => {
            alert(`❌ خطأ: ${error.message}`);
        });
}

// ربط الزر بوظيفة تسجيل الدخول
document.getElementById("google-login-btn").addEventListener("click", googleSignIn);
