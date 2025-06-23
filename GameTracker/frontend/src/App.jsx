import { useState, useEffect, useRef } from 'react'
import { Routes, Route, Link, useLocation, Navigate, useNavigate, useParams } from 'react-router-dom'
import axios from 'axios'
import './App.css'
import { FaSearch, FaBook, FaUsers, FaSignOutAlt, FaLock, FaSortAlphaDown, FaSortNumericDown, FaSortAmountDown, FaCog, FaEnvelope, FaBell, FaCheckCircle, FaRegCalendarAlt, FaArrowLeft, FaPlay, FaHeart, FaEye, FaCheck, FaTh, FaList, FaTrash, FaExclamationCircle } from 'react-icons/fa'
import { useToast } from './contexts/ToastContext'

// Dynamic API base URL that works from any device
//const API_BASE = "http://10.0.0.30:3000/api"
const API_BASE = "/api"
const STATUSES = ['wishlist', 'playing', 'done']
// ${window.location.protocol} ${window.location.hostname}
function useAuth() {
  const [user, setUser] = useState(null)
  useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]))
        setUser(payload)
      } catch {
        setUser(null)
      }
    } else {
      setUser(null)
    }
  }, [])
  return [user, setUser]
}

function App() {
  const [user, setUser] = useAuth()
  const location = useLocation()
  const navigate = useNavigate()

  // Logout function
  const logout = () => {
    localStorage.removeItem('token')
    setUser(null)
    navigate('/login')
  }

  // Determine page title
  let pageTitle = ''
  if (location.pathname.startsWith('/search')) pageTitle = 'Search Games'
  else if (location.pathname.startsWith('/library')) pageTitle = 'My Library'
  else if (location.pathname.startsWith('/calendar')) pageTitle = 'Calendar'
  else if (location.pathname.startsWith('/users')) pageTitle = 'User Management'
  else if (location.pathname.startsWith('/settings')) pageTitle = 'Settings'
  else if (location.pathname.startsWith('/game/')) pageTitle = 'Game Details'

  // If not logged in, render only the login page/route
  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage setUser={setUser} />} />
        <Route path="*" element={<Navigate to="/login" />} />
      </Routes>
    )
  }

  // If logged in, render the full app
  return (
    <div className="container">
      <aside className="sidebar left-sidebar">
        <nav className="nav-menu">
          <Link to="/search" className={location.pathname === '/search' ? 'active' : ''}>
            <FaSearch className="nav-icon" />
            <span className="nav-label">Search Games</span>
          </Link>
          <Link to="/library" className={location.pathname === '/library' ? 'active' : ''}>
            <FaBook className="nav-icon" />
            <span className="nav-label">My Library</span>
          </Link>
          <Link to="/calendar" className={location.pathname === '/calendar' ? 'active' : ''}>
            <FaRegCalendarAlt className="nav-icon" />
            <span className="nav-label">Calendar</span>
          </Link>
          {(user.can_manage_users || user.can_create_users) && (
            <Link to="/users" className={location.pathname === '/users' ? 'active' : ''}>
              <FaUsers className="nav-icon" />
              <span className="nav-label">User Management</span>
            </Link>
          )}
          {user.can_manage_users && (
            <Link to="/settings" className={location.pathname === '/settings' ? 'active' : ''}>
              <FaCog className="nav-icon" />
              <span className="nav-label">Settings</span>
            </Link>
          )}
          <button className="logout-btn" onClick={logout}>
            <FaSignOutAlt className="nav-icon" />
            <span className="nav-label">Logout</span>
          </button>
        </nav>
      </aside>
      <main className="main-content">
        {pageTitle && <div className="page-title">{pageTitle}</div>}
        <Routes>
          <Route path="/search" element={<SearchPage user={user} />} />
          <Route path="/library" element={<LibraryPage user={user} />} />
          <Route path="/calendar" element={<CalendarPage user={user} />} />
          <Route path="/users" element={<UserManagementPage user={user} />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/search" />} />
        </Routes>
      </main>
    </div>
  )
}

function LoginPage({ setUser }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    try {
      const res = await axios.post(`${API_BASE}/auth/login`, { username, password })
      localStorage.setItem('token', res.data.token)
      const payload = JSON.parse(atob(res.data.token.split('.')[1]))
      setUser(payload)
      navigate('/search')
    } catch (err) {
      setError('Invalid username or password')
    }
  }

  return (
    <div className="login-page">
      <form className="login-form" onSubmit={handleLogin}>
        <h2>Login</h2>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={e => setUsername(e.target.value)}
          autoFocus
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={e => setPassword(e.target.value)}
        />
        <button type="submit">Login</button>
        {error && <div className="error-msg">{error}</div>}
      </form>
    </div>
  )
}

function UserManagementPage({ user }) {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [newUser, setNewUser] = useState({ username: '', password: '', can_manage_users: false })
  const [success, setSuccess] = useState('')
  const token = localStorage.getItem('token')
  const [formError, setFormError] = useState('')
  const [modalOpen, setModalOpen] = useState(false)
  const modalRef = useRef()

  const fetchUsers = async () => {
    setLoading(true)
    try {
      const res = await axios.get(`${API_BASE}/users`, { headers: { Authorization: `Bearer ${token}` } })
      setUsers(res.data)
      setLoading(false)
    } catch (err) {
      setError('Failed to load users')
      setLoading(false)
    }
  }
  useEffect(() => { fetchUsers() }, [])

  const handleCreate = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setFormError('')
    // Basic validation
    if (!newUser.username.trim() || !newUser.password.trim()) {
      setFormError('Username and password are required.')
      return
    }
    try {
      await axios.post(`${API_BASE}/users`, newUser, { headers: { Authorization: `Bearer ${token}` } })
      setSuccess('User created!')
      setNewUser({ username: '', password: '', can_manage_users: false })
      fetchUsers()
    } catch (err) {
      setError('Failed to create user')
    }
  }
  const handleDelete = async (id) => {
    if (!window.confirm('Delete this user?')) return
    setError('')
    setSuccess('')
    try {
      await axios.delete(`${API_BASE}/users/${id}`, { headers: { Authorization: `Bearer ${token}` } })
      setSuccess('User deleted!')
      fetchUsers()
    } catch (err) {
      setError('Failed to delete user')
    }
  }
  const handleEdit = async (id, updates) => {
    setError('')
    setSuccess('')
    try {
      await axios.put(`${API_BASE}/users/${id}`, updates, { headers: { Authorization: `Bearer ${token}` } })
      setSuccess('User updated!')
      fetchUsers()
    } catch (err) {
      setError('Failed to update user')
    }
  }

  // Modal close on ESC or background click
  useEffect(() => {
    if (!modalOpen) return;
    function onKey(e) { if (e.key === 'Escape') setModalOpen(false); }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [modalOpen])

  function handleModalBgClick(e) {
    if (e.target === modalRef.current) setModalOpen(false)
  }

  // Modern card-based UI
  return (
    <div className="user-management-page-modern">
      <div className="user-management-toolbar">
        <div>
          <div className="user-mgmt-subtitle">Manage your team members and their account permissions here.</div>
        </div>
        <button className="add-user-btn" onClick={() => setModalOpen(true)}>Add User</button>
      </div>
      {modalOpen && (
        <div className="user-modal-bg" ref={modalRef} onClick={handleModalBgClick} tabIndex={-1} aria-modal="true" role="dialog">
          <div className="user-modal-window">
            <button className="user-modal-close" aria-label="Close" onClick={() => setModalOpen(false)}>&times;</button>
            <form className="user-form-modern user-form-vertical user-form-enhanced" onSubmit={handleCreate} autoFocus>
              <div className="user-form-group">
                <label>Username
                  <input
                    type="text"
                    placeholder="Username"
                    value={newUser.username}
                    onChange={e => setNewUser({ ...newUser, username: e.target.value })}
                    required
                  />
                </label>
                <label>Password
                  <input
                    type="password"
                    placeholder="Password"
                    value={newUser.password}
                    onChange={e => setNewUser({ ...newUser, password: e.target.value })}
                    required
                  />
                </label>
              </div>
              <div className="user-form-group user-form-checkboxes enhanced-toggles" style={{justifyContent: 'flex-start', alignItems: 'center', gap: '2.2rem', marginBottom: '0.5rem'}}>
                <label className="switch-modern enhanced-switch">
                  <input type="checkbox" checked={newUser.can_manage_users} onChange={e => setNewUser({ ...newUser, can_manage_users: e.target.checked })} />
                  <span className="slider-modern enhanced-slider"></span>
                  <span className="switch-label enhanced-switch-label">Admin</span>
                </label>
              </div>
              {formError && <div className="error-msg enhanced-error"><FaExclamationCircle style={{marginRight:6}}/> {formError}</div>}
              <button type="submit" className="create-user-btn enhanced-btn">Create User</button>
            </form>
            {success && <div className="success-msg enhanced-success"><FaCheckCircle style={{marginRight:6}}/> {success}</div>}
            {error && <div className="error-msg enhanced-error"><FaExclamationCircle style={{marginRight:6}}/> {error}</div>}
          </div>
        </div>
      )}
      <div className="user-table-section">
        <table className="user-table-modern">
          <thead>
            <tr>
              <th>Avatar</th>
              <th>Name</th>
              <th>Full name</th>
              <th>Role</th>
              <th>Date Joined</th>
              <th>Permissions</th>
              <th>Source</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map(u => {
              function stringToColor(str) {
                let hash = 0;
                for (let i = 0; i < str.length; i++) hash = str.charCodeAt(i) + ((hash << 5) - hash);
                const h = Math.abs(hash) % 360;
                return `hsl(${h}, 70%, 80%)`;
              }
              const avatarBg = stringToColor(u.username || 'U');
              const avatarLetter = (u.username && u.username.length > 0) ? u.username[0].toUpperCase() : '?';
              let role = 'User';
              if (u.can_manage_users) role = 'Admin';
              // Use real created_at date if available
              let joined = u.created_at ? new Date(u.created_at).toLocaleDateString() : 'Unknown';
              return (
                <tr key={u.id}>
                  <td><div className="user-table-avatar" style={{ background: avatarBg }} aria-label={`Avatar for ${u.username}` }>{avatarLetter}</div></td>
                  <td><span className="user-table-name">{u.username}</span></td>
                  <td><span className="user-table-fullname">{u.display_name || ''}</span></td>
                  <td><span className="user-table-role">{role}</span></td>
                  <td><span className="user-table-date">{joined}</span></td>
                  <td>
                    <div className="user-table-perms">
                      <label className="switch-modern enhanced-switch" title="Toggle Admin Permission">
                        <input
                          type="checkbox"
                          checked={!!u.can_manage_users}
                          disabled={u.username === 'root' || u.id === user.id}
                          onChange={e => handleEdit(u.id, { can_manage_users: e.target.checked })}
                        />
                        <span className="slider-modern enhanced-slider"></span>
                      </label>
                    </div>
                  </td>
                  <td><span className="user-table-source">{u.origin === 'ldap' ? 'LDAP' : 'Local'}</span></td>
                  <td>
                    <div className="user-table-actions">
                      <button className="icon-btn enhanced-icon-btn" title="Change Password" aria-label="Change Password" onClick={() => handleEdit(u.id, { password: prompt('New password:') })}><FaLock /></button>
                      <button className="icon-btn enhanced-icon-btn" title="Delete User" aria-label="Delete User" onClick={() => handleDelete(u.id)} disabled={u.username === 'root'}><FaTrash /></button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function SearchPage({ user }) {
  const [search, setSearch] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [searchError, setSearchError] = useState('')
  const [viewMode, setViewMode] = useState('grid')
  const navigate = useNavigate()
  const { showToast } = useToast();

  // Search games
  const handleSearch = async (e) => {
    e.preventDefault()
    if (!search) return
    setLoading(true)
    setSearchError('')
    try {
      const res = await axios.get(`${API_BASE}/games/search?q=${encodeURIComponent(search)}`)
      setSearchResults(res.data)
    } catch (err) {
      setSearchResults([])
      setSearchError('Failed to search games. Please try again.')
    }
    setLoading(false)
  }

  // Add to library
  const addToLibrary = async (game, unreleased = false) => {
    if (!user) {
      showToast('error', 'You must be logged in to add games.');
      return;
    }
    try {
      // Check for duplicate
      const res = await axios.get(`${API_BASE}/user/${user.username}/games`);
      const alreadyInLibrary = res.data.some(g => {
        const gId = g.gameId || g.game_id;
        const gName = (g.gameName || g.game_name || '').trim().toLowerCase();
        const gameId = game.id || game.game_id;
        const gameName = (game.name || game.game_name || '').trim().toLowerCase();
        return gId === gameId || gName === gameName;
      });
      if (alreadyInLibrary) {
        showToast('error', 'You already have this game in your library!');
        return;
      }
      await axios.post(`${API_BASE}/user/${user.username}/games`, {
        gameId: game.id,
        gameName: game.name,
        coverUrl: game.coverUrl,
        releaseDate: game.releaseDate,
        status: (!game.releaseDate || unreleased) ? 'unreleased' : 'wishlist',
      })
      showToast('success', `Added ${game.name} to your library!`);
    } catch (err) {
      showToast('error', 'Failed to add to library.');
    }
  }

  return (
    <div className="results-section">
      <div className="search-controls-header">
        <form onSubmit={handleSearch} className="search-bar sonarr-style">
          <label htmlFor="search-input" className="visually-hidden">Search Games</label>
          <input
            id="search-input"
            type="text"
            placeholder="Search for games..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            autoComplete="off"
          />
          <button type="submit" className="search-icon-btn" aria-label="Search">
            <FaSearch />
          </button>
        </form>
        <div className="view-controls">
          <div className="view-toggle">
            <button onClick={() => setViewMode('grid')} className={`view-btn ${viewMode === 'grid' ? 'active' : ''}`}><FaTh /></button>
            <button onClick={() => setViewMode('list')} className={`view-btn ${viewMode === 'list' ? 'active' : ''}`}><FaList /></button>
          </div>
        </div>
      </div>
      {loading && <p>Searching...</p>}
      {searchError && <div className="error-msg">{searchError}</div>}
      {searchResults.length > 0 && (
        <>
          <h2>Search Results</h2>
          <div className={`games-list ${viewMode === 'list' ? 'list-view' : 'grid-view'}`}>
            {searchResults.map(game => {
              // Determine if unreleased
              let unreleased = false;
              if (!game.releaseDate) {
                unreleased = true;
              } else {
                const today = new Date();
                const release = new Date(game.releaseDate);
                unreleased = release > today;
              }
              return (
                <div key={game.id} className={`game-card ${viewMode === 'list' ? 'list-item' : ''}`} >
                  {game.coverUrl && (
                    <div className="game-cover-container">
                      <img src={game.coverUrl} alt={game.name} className="game-cover" />
                    </div>
                  )}
                  <div className="game-info">
                    <div className="game-title">{game.name}</div>
                    <div className="game-release-date">
                      Release: {game.releaseDate ? game.releaseDate : 'Unreleased'}
                      {unreleased && <span className="unreleased-pill">Unreleased</span>}
                    </div>
                    <button
                      className="add-btn"
                      onClick={e => { e.stopPropagation(); addToLibrary(game, unreleased); }}
                    >
                      Add to Library
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  )
}

function LibraryPage({ user }) {
  const [userGames, setUserGames] = useState([])
  const [loading, setLoading] = useState(false)
  const [statusUpdating, setStatusUpdating] = useState(false)
  const [filter, setFilter] = useState('all')
  const [statusError, setStatusError] = useState('')
  const [removeError, setRemoveError] = useState('')
  const [sortBy, setSortBy] = useState('name')
  const [sortDir, setSortDir] = useState('asc')
  const [viewMode, setViewMode] = useState('grid')
  const [currentPage, setCurrentPage] = useState(1)
  const gamesPerPage = 15

  useEffect(() => {
    if (user) {
      setLoading(true)
      axios.get(`${API_BASE}/user/${user.username}/games`).then(res => {
        setUserGames(res.data)
        setLoading(false)
      })
    } else {
      setUserGames([])
    }
  }, [user, statusUpdating])

  const FILTERS = [
    { label: 'All', value: 'all' },
    { label: 'Wishlist', value: 'wishlist' },
    { label: 'Playing', value: 'playing' },
    { label: 'Done', value: 'done' },
    { label: 'Unreleased', value: 'unreleased' },
  ]
  
  let filteredUserGames = filter === 'all'
    ? userGames
    : userGames.filter(game => {
        if (filter === 'unreleased') {
          return game.status === 'unreleased' || !game.release_date;
        }
        return game.status === filter;
      });

  // Sorting logic
  filteredUserGames = [...filteredUserGames].sort((a, b) => {
    if (sortBy === 'name') {
      return sortDir === 'asc'
        ? a.game_name.localeCompare(b.game_name)
        : b.game_name.localeCompare(a.game_name)
    } else if (sortBy === 'release') {
      return sortDir === 'asc'
        ? (a.release_date || '').localeCompare(b.release_date || '')
        : (b.release_date || '').localeCompare(a.release_date || '')
    } else if (sortBy === 'status') {
      return sortDir === 'asc'
        ? a.status.localeCompare(b.status)
        : b.status.localeCompare(a.status)
    }
    return 0
  })

  // Pagination
  const totalPages = Math.ceil(filteredUserGames.length / gamesPerPage)
  const indexOfLastGame = currentPage * gamesPerPage
  const indexOfFirstGame = indexOfLastGame - gamesPerPage
  const currentGames = filteredUserGames.slice(indexOfFirstGame, indexOfLastGame)

  // Change status
  const setGameStatus = async (game, status) => {
    if (!user) return alert('Enter a username first!')
    setStatusUpdating(true)
    setStatusError('')
    try {
      await axios.post(`${API_BASE}/user/${user.username}/games`, {
        gameId: game.game_id,
        gameName: game.game_name,
        coverUrl: game.cover_url,
        releaseDate: game.release_date,
        status,
      })
    } catch (err) {
      setStatusError('Failed to update status. Please try again.')
    }
    setStatusUpdating(false)
  }

  // Remove game
  const removeGame = async (gameId) => {
    if (!user) return
    setStatusUpdating(true)
    setRemoveError('')
    try {
      await axios.delete(`${API_BASE}/user/${user.username}/games/${gameId}`)
    } catch (err) {
      setRemoveError('Failed to remove game. Please try again.')
    }
    setStatusUpdating(false)
  }

  const handleSortClick = (value) => {
    if (sortBy === value) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(value)
      setSortDir('asc')
    }
  }

  const sortOptions = [
    { label: 'Name', value: 'name' },
    { label: 'Release Date', value: 'release' },
    { label: 'Status', value: 'status' },
  ]

  return (
    <div className="user-games-section">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2 style={{margin: 0}}>My Library ({userGames.length})</h2>
        <div className="view-controls">
          <div className="view-toggle">
            <button onClick={() => setViewMode('grid')} className={`view-btn ${viewMode === 'grid' ? 'active' : ''}`}><FaTh /></button>
            <button onClick={() => setViewMode('list')} className={`view-btn ${viewMode === 'list' ? 'active' : ''}`}><FaList /></button>
          </div>
        </div>
      </div>

      <div className="filter-bar">
        {FILTERS.map(f => (
          <button
            key={f.value}
            className={`filter-btn${filter === f.value ? ' active' : ''}`}
            onClick={() => { setFilter(f.value); setCurrentPage(1); }}
            disabled={statusUpdating}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="sort-bar">
        Sort by:
        {sortOptions.map(opt => (
          <button
            key={opt.value}
            className={`sort-btn${sortBy === opt.value ? ' active' : ''}`}
            onClick={() => handleSortClick(opt.value)}
          >
            {opt.label}
            {sortBy === opt.value && (
              <span style={{marginLeft: 4, fontWeight: 700}}>
                {sortDir === 'asc' ? '▲' : '▼'}
              </span>
            )}
          </button>
        ))}
      </div>

      {statusError && <div className="error-msg">{statusError}</div>}
      {removeError && <div className="error-msg">{removeError}</div>}
      
      {loading ? (
        <p>Loading...</p>
      ) : filteredUserGames.length === 0 ? (
        <p>No games in your library yet.</p>
      ) : (
        <>
          <div className={`games-list ${viewMode === 'list' ? 'list-view' : ''}`}>
            {currentGames.map(game => {
              const isUnreleased = game.status === 'unreleased' || !game.release_date;
              return (
                <div key={game.game_id} className={`game-card ${viewMode === 'list' ? 'list-item' : ''}`} >
                  {game.cover_url && (
                    <div className="game-cover-container">
                      <img src={game.cover_url} alt={game.game_name} className="game-cover" />
                    </div>
                  )}
                  <div className="game-info">
                    <div>
                      <div className="game-title">{game.game_name}</div>
                      <div className="game-release-date">Release: {game.release_date ? game.release_date : 'Unreleased'}</div>
                    </div>
                    <div className="game-card-actions">
                      {isUnreleased ? (
                        <div className="unreleased-indicator">
                          <FaLock /> Unreleased
                        </div>
                      ) : (
                        <select 
                          className="status-select" 
                          value={game.status} 
                          onChange={(e) => {
                            e.stopPropagation();
                            setGameStatus(game, e.target.value);
                          }}
                          onClick={(e) => e.stopPropagation()}
                        >
                          {STATUSES.map(status => (
                            <option key={status} value={status}>{status}</option>
                          ))}
                        </select>
                      )}
                      <button 
                        className="remove-btn-icon"
                        onClick={(e) => {
                          e.stopPropagation();
                          removeGame(game.game_id);
                        }}
                      >
                        <FaTrash />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          
          {/* Pagination Controls */}
          <div className="pagination-controls">
            <button 
              className="pagination-btn" 
              onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
              disabled={currentPage === 1}
            >
              Previous
            </button>
            <span className="pagination-info">
              Page {currentPage} of {totalPages}
            </span>
            <button 
              className="pagination-btn" 
              onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
              disabled={currentPage === totalPages}
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  )
}

function CalendarPage({ user }) {
  const [userGames, setUserGames] = useState([]);
  const [month, setMonth] = useState(() => {
    const today = new Date();
    return { year: today.getFullYear(), month: today.getMonth() };
  });

  useEffect(() => {
    if (user) {
      axios.get(`${API_BASE}/user/${user.username}/games`).then(res => {
        setUserGames(res.data);
      });
    }
  }, [user]);

  // Build a map of release dates to games
  const dateMap = {};
  userGames.forEach(game => {
    if (game.release_date) {
      dateMap[game.release_date] = dateMap[game.release_date] || [];
      dateMap[game.release_date].push(game);
    }
  });

  // Calendar grid for selected month
  const year = month?.year ?? new Date().getFullYear();
  const m = month?.month ?? new Date().getMonth();
  const firstDay = new Date(year, m, 1);
  const lastDay = new Date(year, m + 1, 0);
  const daysInMonth = lastDay.getDate();
  const startDay = firstDay.getDay();

  // Build a 6-row (max) calendar grid (7 days per week)
  const calendarCells = [];
  let dayNum = 1 - startDay;
  for (let week = 0; week < 6; week++) {
    for (let d = 0; d < 7; d++) {
      const cellDate = new Date(year, m, dayNum);
      calendarCells.push(cellDate);
      dayNum++;
    }
  }

  const today = new Date();
  const isToday = (date) =>
    date.getFullYear() === today.getFullYear() &&
    date.getMonth() === today.getMonth() &&
    date.getDate() === today.getDate();

  const isCurrentMonth = (date) => date.getMonth() === m && date.getFullYear() === year;

  const monthNames = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'
  ];
  const weekdayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

  const handlePrevMonth = () => {
    setMonth(prev => {
      let newMonth = prev.month - 1;
      let newYear = prev.year;
      if (newMonth < 0) {
        newMonth = 11;
        newYear--;
      }
      return { year: newYear, month: newMonth };
    });
  };
  const handleNextMonth = () => {
    setMonth(prev => {
      let newMonth = prev.month + 1;
      let newYear = prev.year;
      if (newMonth > 11) {
        newMonth = 0;
        newYear++;
      }
      return { year: newYear, month: newMonth };
    });
  };

  return (
    <div className="calendar-section">
      <div className="calendar-header">
        <button className="calendar-nav-btn" onClick={handlePrevMonth}>&lt;</button>
        <span className="calendar-month-label">{monthNames[m]} {year}</span>
        <button className="calendar-nav-btn" onClick={handleNextMonth}>&gt;</button>
      </div>
      <div className="calendar-grid calendar-grid-full">
        {weekdayNames.map((wd, i) => (
          <div key={wd} className="calendar-cell calendar-weekday">{wd}</div>
        ))}
        {calendarCells.map((date, idx) => {
          const dateStr = date.toISOString().split('T')[0];
          const games = dateMap[dateStr] || [];
          return (
            <div
              key={idx}
              className={`calendar-cell${isCurrentMonth(date) ? '' : ' calendar-other-month'}${isToday(date) ? ' calendar-today' : ''}`}
            >
              <div className="calendar-date">{date.getDate()}</div>
              {games.length > 0 && (
                <div className="calendar-games-list">
                  {games.map(game => (
                    <div key={game.game_id} className="calendar-game-title-small">{game.game_name}</div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SettingsPage() {
  const [smtp, setSmtp] = useState(() => JSON.parse(localStorage.getItem('smtp_settings') || '{}'));
  const [ntfy, setNtfy] = useState(() => JSON.parse(localStorage.getItem('ntfy_settings') || '{}'));
  const [ldap, setLdap] = useState(() => JSON.parse(localStorage.getItem('ldap_settings') || '{}'));
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');
  const user = JSON.parse(localStorage.getItem('token_payload') || '{}');
  const isAdmin = user && user.can_manage_users;

  const handleSmtpChange = e => setSmtp({ ...smtp, [e.target.name]: e.target.value });
  const handleNtfyChange = e => setNtfy({ ...ntfy, [e.target.name]: e.target.value });
  const handleLdapChange = e => setLdap({ ...ldap, [e.target.name]: e.target.value });

  const handleSave = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await axios.post(`${API_BASE}/settings`, { smtp, ntfy, ldap });
      localStorage.setItem('smtp_settings', JSON.stringify(smtp));
      localStorage.setItem('ntfy_settings', JSON.stringify(ntfy));
      localStorage.setItem('ldap_settings', JSON.stringify(ldap));
      setSuccess(true);
      setTimeout(() => setSuccess(false), 2000);
    } catch (err) {
      setError('Failed to save settings.');
    }
  };

  // Decode token to check admin
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        localStorage.setItem('token_payload', JSON.stringify(payload));
      } catch {}
    }
  }, []);

  return (
    <div className="settings-page">
      <h2><FaCog style={{marginRight:8}}/>Settings</h2>
      <form className="settings-form" onSubmit={handleSave}>
        <div className="settings-columns">
          {isAdmin && (
            <fieldset>
              <legend><FaEnvelope style={{marginRight:6}}/>Email (SMTP) Notifications</legend>
              <div className="input-group">
                <label htmlFor="smtp-host">SMTP Host</label>
                <input id="smtp-host" name="host" value={smtp.host || ''} onChange={handleSmtpChange} placeholder="e.g. smtp.example.com" />
              </div>
              <div className="input-group">
                <label htmlFor="smtp-port">SMTP Port</label>
                <input id="smtp-port" name="port" value={smtp.port || ''} onChange={handleSmtpChange} placeholder="e.g. 587" type="number" />
              </div>
              <div className="input-group">
                <label htmlFor="smtp-user">SMTP Username</label>
                <input id="smtp-user" name="user" value={smtp.user || ''} onChange={handleSmtpChange} placeholder="e.g. user@example.com" />
              </div>
              <div className="input-group">
                <label htmlFor="smtp-pass">SMTP Password</label>
                <input id="smtp-pass" name="pass" value={smtp.pass || ''} onChange={handleSmtpChange} placeholder="Password" type="password" />
              </div>
              <div className="input-group">
                <label htmlFor="smtp-from">From Email</label>
                <input id="smtp-from" name="from" value={smtp.from || ''} onChange={handleSmtpChange} placeholder="e.g. noreply@example.com" />
              </div>
              <div className="input-group">
                <label htmlFor="smtp-to">Your Email (to receive notifications)</label>
                <input id="smtp-to" name="to" value={smtp.to || ''} onChange={handleSmtpChange} placeholder="e.g. you@example.com" />
              </div>
            </fieldset>
          )}

          {isAdmin && (
            <fieldset>
              <legend><FaBell style={{marginRight:6}}/>ntfy Notifications</legend>
              <div className="input-group">
                <label htmlFor="ntfy-url">ntfy Server URL</label>
                <input id="ntfy-url" name="url" value={ntfy.url || ''} onChange={handleNtfyChange} placeholder="e.g. https://ntfy.example.com" />
              </div>
              <div className="input-group">
                <label htmlFor="ntfy-topic">ntfy Topic</label>
                <input id="ntfy-topic" name="topic" value={ntfy.topic || ''} onChange={handleNtfyChange} placeholder="e.g. mytopic" />
              </div>
            </fieldset>
          )}

          {isAdmin && (
            <fieldset>
              <legend><FaLock style={{marginRight:6}}/>LDAP Settings</legend>
              <div className="input-group">
                <label htmlFor="ldap-url">LDAP Server URL</label>
                <input id="ldap-url" name="url" value={ldap.url || ''} onChange={handleLdapChange} placeholder="e.g. ldap://dc01.example.com" />
              </div>
              <div className="input-group">
                <label htmlFor="ldap-base">Base DN</label>
                <input id="ldap-base" name="base" value={ldap.base || ''} onChange={handleLdapChange} placeholder="e.g. dc=example,dc=com" />
              </div>
              <div className="input-group">
                <label htmlFor="ldap-userdn">User DN Pattern</label>
                <input id="ldap-userdn" name="userDn" value={ldap.userDn || ''} onChange={handleLdapChange} placeholder="e.g. cn={username},ou=Users,{baseDN}" />
              </div>
              <div className="input-group">
                <label htmlFor="ldap-binddn">Bind DN (optional)</label>
                <input id="ldap-binddn" name="bindDn" value={ldap.bindDn || ''} onChange={handleLdapChange} placeholder="e.g. cn=readonly,dc=example,dc=com" />
              </div>
              <div className="input-group">
                <label htmlFor="ldap-bindpass">Bind Password (optional)</label>
                <input id="ldap-bindpass" name="bindPass" value={ldap.bindPass || ''} onChange={handleLdapChange} placeholder="Password" type="password" />
              </div>
              <div className="input-group">
                <label htmlFor="ldap-requiredgroup">Required Group</label>
                <input id="ldap-requiredgroup" name="requiredGroup" value={ldap.requiredGroup || ''} onChange={handleLdapChange} placeholder="e.g. GameTrackerUsers or cn=..." />
              </div>
            </fieldset>
          )}
        </div>

        <button type="submit" className="save-settings-btn enhanced-btn">Save Settings</button>
        {success && <div className="settings-success"><FaCheckCircle style={{color:'#43a047',marginRight:6}}/>Settings saved!</div>}
        {error && <div className="error-msg">{error}</div>}
      </form>
    </div>
  );
}

export default App
