import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useStore } from '../store'

import API_URL from '../config';

const API = API_URL;

export default function Register() {
  const nav = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [ok, setOk] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const r = await fetch(`${API}/api/auth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) })
      const j = await r.json().catch(() => ({ error: 'Register failed' }))
      if (!r.ok) {
        setError(j.error || 'Register failed')
      } else {
        setOk(true)
        setTimeout(() => nav('/login'), 800)
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="h-screen grid place-items-center bg-sky-50">
      <form onSubmit={submit} className="w-[380px] bg-white rounded-2xl shadow-soft p-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-9 h-9 rounded-full bg-yellow-400 grid place-items-center font-bold">💬</div>
          <div className="font-semibold text-lg">XevyTalk</div>
        </div>
        <div className="text-xl font-semibold mb-4">Create account</div>
        {error && <div className="text-sm text-red-600 mb-3">{error}</div>}
        {ok && <div className="text-sm text-green-600 mb-3">Account created. Redirecting to login…</div>}
        <div className="space-y-3">
          <input value={username} onChange={e => setUsername(e.target.value)} className="w-full rounded-xl border-0 bg-sky-50 px-3 py-2" placeholder="Username" required />
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} className="w-full rounded-xl border-0 bg-sky-50 px-3 py-2" placeholder="Password" required />
          <button disabled={loading} className="w-full bg-primary text-white rounded-xl py-2 disabled:opacity-50">{loading ? 'Creating...' : 'Create account'}</button>
        </div>
        <div className="text-sm text-gray-600 mt-4">Already have an account? <Link className="text-primary" to="/login">Sign in</Link></div>
      </form>
    </div>
  )
}
