// Script to manually trigger notification checks
const { getAllUsers, getUserGames, wasNotificationSent, markNotificationSent, sendReleaseReminder } = require('./index.js');

console.log('[MANUAL] Running notification check...');
getAllUsers((err, users) => {
  if (err) return console.error('Error fetching users for notifications:', err);
  users.forEach(username => {
    getUserGames(username, (err, games) => {
      if (err) return;
      let found = false;
      games.forEach(game => {
        if (game.status === 'unreleased' && game.release_date) {
          const releaseDate = new Date(game.release_date);
          const today = new Date();
          today.setHours(0,0,0,0);
          releaseDate.setHours(0,0,0,0);
          const diffDays = Math.ceil((releaseDate - today) / (1000 * 60 * 60 * 24));
          console.log(`[MANUAL] User: ${username}, Game: ${game.game_name}, Release: ${game.release_date}, diffDays: ${diffDays}`);
          let type = null;
          if (diffDays === 30) type = '30days';
          if (diffDays === 7) type = '7days';
          if (diffDays === 0) type = 'release';
          if (type && !wasNotificationSent(username, game.game_id, type)) {
            console.log(`[MANUAL] Sending ${type} reminder to ${username} for game ${game.game_name}`);
            sendReleaseReminder(username, game, diffDays).then(() => {
              markNotificationSent(username, game.game_id, type);
              console.log(`Sent ${type} release reminder to ${username} for game ${game.game_name}`);
            }).catch(err => {
              console.error(`Failed to send ${type} reminder to ${username} for game ${game.game_name}:`, err);
            });
            found = true;
          } else if (type && wasNotificationSent(username, game.game_id, type)) {
            console.log(`[MANUAL] Notification already sent for ${username}, game ${game.game_name}, type ${type}`);
          }
        }
      });
      if (!found) {
        console.log(`[MANUAL] No matching unreleased games for user ${username}`);
      }
    });
  });
}); 