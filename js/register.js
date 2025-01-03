
    const baseUrl = "http://localhost:8080";

    async function checkLoginStatus() {
    const response = await fetch(`${baseUrl}/checkLoginStatus`, {
    method: 'GET',
    credentials: 'same-origin',
});
    const result = await response.json();

    if (result.status === "logged_in") {
    // Если пользователь залогинен, перенаправляем на главную страницу
    window.location.href = "/mainPage";
}
}

    // Функция для перехода на страницу входа
    async function goToLogin() {
    checkLoginStatus(); // Проверяем статус пользователя
    window.location.href = "/loginPage"; // Переход на страницу логина
}

    // Создание нового пользователя
    async function createUser() {
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const password2 = document.getElementById("password2").value;

    if(!email || !password || !password2){
    alert("Fill all the fields")
    return
}

    if(password !== password2){
    alert("Password doesn't match")
    return
}

    try {
    const response = await fetch(`${baseUrl}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
});

    const result = await response.json();

    if (response.ok) {
    alert(result.message);
    window.location.href = "/loginPage"; // После регистрации идем на страницу логина
} else {
    alert(result.message || "Registration failed");
}
} catch (error) {
    alert("An error occurred: " + error.message);
}

    // Очистка полей
    document.getElementById("email").value = "";
    document.getElementById("password").value = "";
    document.getElementById("password2").value = "";
}