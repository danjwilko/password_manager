
// accounts/script_utils.js
document.addEventListener('DOMContentLoaded', function() {
    const toggleButton = document.getElementById('toggle_password');
    const passwordInput = document.getElementById('password-input');
    
    if (!toggleButton || !passwordInput) return;

    toggleButton.addEventListener('click', function(event) {
        event.preventDefault();

        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleButton.textContent = 'Hide Password';
        } else {
            passwordInput.type = 'password';
            toggleButton.textContent = 'Show Password';
        }
    });
    passwordInput.addEventListener('blur', () => {
    if (passwordInput.type === 'text') {
      passwordInput.type = 'password';
      if (toggleButton) {
        toggleButton.textContent = 'Show password';
        toggleButton.setAttribute('aria-pressed', 'false');
      }
    }
  });
});

