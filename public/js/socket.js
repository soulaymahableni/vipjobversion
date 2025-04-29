// Initialize Socket.IO connection
const socket = io();

// Get user ID from localStorage
const userId = localStorage.getItem('userId');

// Join user's room when connected
socket.on('connect', () => {
  console.log('Connected to WebSocket server');
  if (userId) {
    socket.emit('join-room', userId);
  }
});

// Handle new offer notifications
socket.on('new-offre-notification', (data) => {
  console.log('New offer notification received:', data);
  
  // Create notification element
  const notification = document.createElement('div');
  notification.className = 'notification';
  notification.innerHTML = `
    <div class="notification-content">
      <h3>${data.title}</h3>
      <p>Domaine: ${data.domaine}</p>
      <p>Type: ${data.type}</p>
      <p>Lieu: ${data.location}</p>
      <p>Début: ${data.startDate}</p>
      <p>Fin: ${data.endDate}</p>
    </div>
  `;

  // Add notification to the page
  const notificationContainer = document.getElementById('notification-container');
  if (notificationContainer) {
    notificationContainer.appendChild(notification);
    
    // Remove notification after 5 seconds
    setTimeout(() => {
      notification.remove();
    }, 5000);
  }
});

// Handle connection errors
socket.on('connect_error', (error) => {
  console.error('WebSocket connection error:', error);
});

// Handle disconnection
socket.on('disconnect', () => {
  console.log('Disconnected from WebSocket server');
}); 