
    const baseUrl = "http://localhost:8080";
    async function goToReg(){
    window.location.href = "/registerPage";
}
    async function login() {
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    // Validation
    if (!email || !password) {
    alert("Email and password are required.");
    return;
}

    try {
    const response = await fetch("http://localhost:8080/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
});

    const result = await response.json();

    if (result.status === "success") {
    alert("You logged in successfully");
    window.location.href = "/mainPage"; // Redirect to the main page
} else {
    alert(result.message);
}
} catch (error) {
    alert("An error occurred: " + error.message);
}
}
