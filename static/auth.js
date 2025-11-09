document.addEventListener('DOMContentLoaded', async function () {
    if (window.location.pathname === '/login' || window.location.pathname === '/register') {
        console.log('Skipping session check for login/register page');
        return;
    }
    console.log('Checking session validity');
    try {
        const response = await fetch('/api/dashboard', {
            method: 'GET',
            credentials: 'include'
        });
        if (!response.ok) {
            console.log('Session invalid, status:', response.status);
            alert('Your session has expired. Please log in again.');
            window.location.href = '/login';
        } else {
            console.log('Session valid');
        }
    } catch (error) {
        console.error('Session check error:', error);
        alert('Session check failed. Please log in again.');
        window.location.href = '/login';
    }
});

window.addEventListener('beforeunload', function () {
    console.log('Tab closing, attempting logout');
    try {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/logout', false); // Synchronous
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send();
        console.log('Logout request sent');
    } catch (error) {
        console.error('Logout on tab close failed:', error);
    }
});

function handleLoginSuccess() {
    console.log('Login successful');
    window.location.href = '/dashboard';
}