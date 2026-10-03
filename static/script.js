const passwordInput = document.getElementById("password");
const strengthText = document.getElementById("live-strength-text");
const strengthFill = document.getElementById("live-strength-fill");
const feedbackList = document.getElementById("live-feedback");

if (passwordInput) {

    passwordInput.addEventListener("input", function () {

        const password = passwordInput.value;

        let score = 0;
        let feedback = [];

        if (password.length === 0) {
            strengthText.textContent = "Very Weak";
            strengthFill.style.width = "0%";
            feedbackList.innerHTML = "";
            return;
        }

        // Lowercase
        if (/[a-z]/.test(password)) {
            score++;
        } else {
            feedback.push("Add lowercase letters.");
        }

        // Uppercase
        if (/[A-Z]/.test(password)) {
            score++;
        } else {
            feedback.push("Add uppercase letters.");
        }

        // Numbers
        if (/[0-9]/.test(password)) {
            score++;
        } else {
            feedback.push("Add numbers.");
        }

        // Special characters
        if (/[^A-Za-z0-9]/.test(password)) {
            score++;
        } else {
            feedback.push("Add special characters.");
        }

        // Length
        if (password.length >= 8) {
            score++;
        } else {
            feedback.push("Use at least 8 characters.");
        }

        // Extra length
        if (password.length >= 12) {
            score++;
        }

        // Strength
        let strength;

        if (score <= 1) {
            strength = "Very Weak";
        } else if (score <= 2) {
            strength = "Weak";
        } else if (score <= 4) {
            strength = "Moderate";
        } else if (score === 5) {
            strength = "Strong";
        } else {
            strength = "Very Strong";
        }

        strengthText.textContent = strength;

        // Meter width
        const width = (score / 6) * 100;
        strengthFill.style.width = width + "%";
        if (score <= 1) {
            strengthFill.style.background = "#ef4444";
        }else if (score <= 2) {
            strengthFill.style.background = "#f97316";
        } else if (score <= 4) {
            strengthFill.style.background = "#f59e0b";
        } else if (score === 5) {
            strengthFill.style.background = "#84cc16";
        } else {
            strengthFill.style.background = "#22c55e";
        }

        // Feedback
        feedbackList.innerHTML = "";

        feedback.forEach(function (item) {

            const li = document.createElement("li");
            li.textContent = item;

            feedbackList.appendChild(li);

        });

    });
}