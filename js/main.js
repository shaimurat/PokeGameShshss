
    const baseUrl = "http://localhost:8080";

    async function logOut(){
    const response = await fetch(`${baseUrl}/logout`, {
    method: 'POST',
    credentials: 'same-origin',
});


        const result = await response.json();

    if (response.ok) {
    alert(result.message)
    window.location.href = "/loginPage";
} else {
    alert("Error logging out: " + result.message);
}
}
    async function sendEmail() {
    const subject = document.getElementById("subject").value;
    const body = document.getElementById("body").value
    if (!subject.trim() || !body.trim()) {
    alert("Subject and body are required.");
    return;
}

    const emailData = {
    subject: subject,
    body: body
}
    const response = await fetch(`http://localhost:8080/sendEmail`, {
    method: "POST",
    headers:{"Content-type":"application/json"},
    body: JSON.stringify(emailData)
})
    const result = await response.json()
    if (response.ok){
    alert(result.message)
}
    else{
    alert("An error occurred: " + result.message);
}
}

    document.addEventListener("DOMContentLoaded", async () => {
        try {
            const response = await fetch("/getUserEmail");
            if (!response.ok) {
                throw new Error("Failed to fetch user email");
            }

            const data = await response.json();
            const userEmail = data.email;

            if (userEmail) {
                document.getElementById("user-email").textContent = userEmail;
            } else {
                console.error("Email not found");
            }
        } catch (error) {
            console.error("Error fetching user email:", error);
        }
    });

