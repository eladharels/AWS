# GameTracker Backend

A Node.js/Express backend for tracking games, their metadata, and user play status.

## Features
- Search games using IGDB API
- Track user game status (playing, will play, done)
- SQLite database for persistence

## Setup
1. **Install dependencies:**
   ```bash
   npm install
   ```
2. **Environment variables:**
   Create a `.env` file with your IGDB credentials:
   ```env
   IGDB_CLIENT_ID=your_igdb_client_id
   IGDB_BEARER_TOKEN=your_igdb_bearer_token
   ```
3. **Run the server:**
   ```bash
   node index.js
   ```

## API Endpoints
### Health Check
- `GET /api/health`

### Search Games
- `GET /api/games/search?q=game_name`

### User Game Status
- `POST /api/user/:username/games`
  - Body: `{ gameId, gameName, coverUrl, releaseDate, status }`
- `GET /api/user/:username/games`

## Docker
To be added. 