import React, { useEffect, useState } from 'react'
import { useStore } from './store'

import API_URL from './config';

const API = API_URL;

export default function NewChatModal({ onClose }) {
  const { user, token, setConversations, setActiveId, setLeftTab } = useStore()
  const [users, setUsers] = useState([])
  const [mode, setMode] = useState('direct')
  const [selected, setSelected] = useState(new Set())
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    ; (async () => {
      const r = await fetch(`${API}/api/users`)
      const u = await r.json()
      setUsers(u.filter(x => x._id !== user._id))
    })()
  }, [])

  const createDirect = async (id) => {
    setLoading(true)
    const r = await fetch(`${API}/api/conversations/direct`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ userId: id }) })
    const conv = await r.json()
    setConversations(cs => {
      const exists = cs.find(c => c._id === conv._id)
      return exists ? cs : [conv, ...cs]
    })
    setActiveId(conv._id)
    onClose()
  }

  const toggle = (id) => {
    const s = new Set(selected)
    if (s.has(id)) s.delete(id); else s.add(id)
    setSelected(s)
  }

  const createGroup = async () => {
    if (!name.trim()) {
      setError('Group name is required')
      return
    }
    if (selected.size < 2) {
      setError('Select at least 2 people for a group')
      return
    }
    setLoading(true)
    setError('')
    const r = await fetch(`${API}/api/conversations/group`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ name, memberIds: [...selected] }) })
    if (!r.ok) {
      const j = await r.json().catch(() => ({ error: 'Failed to create group' }))
      setError(j.error || 'Failed to create group')
    } else {
      const conv = await r.json()
      setConversations(cs => [conv, ...cs])
      setActiveId(conv._id)
      setLeftTab('group')
      onClose()
    }
  }

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50">
      <div className="w-[720px] bg-white rounded-2xl shadow-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="font-semibold text-lg">Start new chat</div>
          <button className="text-gray-500" onClick={onClose}>✕</button>
        </div>
        <div className="flex items-center gap-3 mb-4">
          <button onClick={() => setMode('direct')} className={`px-3 py-2 rounded-lg ${mode === 'direct' ? 'bg-primary text-white' : 'bg-gray-100'}`}>Direct</button>
          <button onClick={() => setMode('group')} className={`px-3 py-2 rounded-lg ${mode === 'group' ? 'bg-primary text-white' : 'bg-gray-100'}`}>Group</button>
        </div>
        {mode === 'group' && (
          <div className="mb-4">
            <input value={name} onChange={e => setName(e.target.value)} className="w-full rounded-xl border-0 bg-sky-50 px-3 py-2" placeholder="Group name" />
          </div>
        )}
        {error && <div className="text-sm text-red-600 mb-2">{error}</div>}
        <div className="max-h-[360px] overflow-y-auto space-y-2 pr-2">
          {users.map(u => (
            <div key={u._id} className="flex items-center justify-between bg-sky-50 rounded-xl px-3 py-2">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 grid place-items-center font-semibold">{u.username?.charAt(0)?.toUpperCase()}</div>
                <div className="text-sm font-medium">{u.username}</div>
              </div>
              {mode === 'direct' ? (
                <button onClick={() => createDirect(u._id)} className="text-xs bg-primary text-white rounded-lg px-3 py-1">Start</button>
              ) : (
                <label className="inline-flex items-center gap-2 text-sm"><input type="checkbox" checked={selected.has(u._id)} onChange={() => toggle(u._id)} className="rounded" /> Select</label>
              )}
            </div>
          ))}
        </div>
        {mode === 'group' && (
          <div className="mt-4 flex justify-end">
            <button onClick={createGroup} disabled={loading || !name.trim() || selected.size < 2} className="bg-primary text-white rounded-lg px-4 py-2 disabled:opacity-50">Create Group</button>
          </div>
        )}
      </div>
    </div>
  )
}
