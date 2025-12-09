import React, { useEffect, useRef, useState, useMemo } from 'react'
import EmojiPicker from 'emoji-picker-react'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import { useStore } from './store'
import { createSocket } from './socket'
import NewChatModal from './NewChatModal'
import CallPage from './CallPage'
import AddMemberModal from './AddMemberModal'
import { useNavigate } from 'react-router-dom'
import { generateKey, exportKey, importKey, encryptMessage, decryptMessage, isEncrypted } from './crypto'

dayjs.extend(relativeTime)

import API_URL from './config';

const API = API_URL;



function VideoTile({ stream, muted }) {
  const ref = useRef(null)
  useEffect(() => {
    if (ref.current) {
      ref.current.srcObject = stream || null
      // Ensure audio is enabled and volume is set
      if (!muted && ref.current) {
        ref.current.volume = 1.0
        ref.current.muted = false
      }
    }
  }, [stream, muted])
  return (
    <video
      ref={ref}
      autoPlay
      playsInline
      muted={muted}
      className="w-full h-full object-cover rounded-xl bg-black"
    />
  )
}

function CallOverlay({ call, localStream, remoteStreams, onEnd, conversation, currentUserId }) {
  const members = Array.isArray(conversation?.members) ? conversation.members : []
  const getNameForUser = (userId) => {
    if (!userId) return 'User'
    if (String(userId) === String(currentUserId)) return 'You'
    const m = members.find(x => String(x._id) === String(userId))
    return m?.username || 'User'
  }
  const remotePrimaryName = call.from?._id && String(call.from._id) !== String(currentUserId)
    ? (members.find(x => String(x._id) === String(call.from._id))?.username || call.from.username || 'User')
    : (members.find(x => String(x._id) !== String(currentUserId))?.username || 'User')
  const isGroup = conversation?.type === 'group' || call.isGroup
  const targetName = isGroup ? (conversation?.name || 'Group') : remotePrimaryName
  const title = call.kind === 'video'
    ? (isGroup ? `Video call from ${targetName}` : `Video call with ${targetName}`)
    : (isGroup ? `Audio call from ${targetName}` : `Audio call with ${targetName}`)
  return (
    <div className="fixed inset-0 z-40 bg-black/40 flex items-center justify-center">
      <div className="w-full max-w-4xl h-[70vh] bg-white rounded-3xl shadow-2xl overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-4 py-3 bg-sky-50 border-b border-sky-100 text-gray-900">
          <div>
            <div className="font-semibold text-sm">{title}</div>
            <div className="text-xs text-gray-500">
              {isGroup ? (conversation?.name || 'Group') : remotePrimaryName}
            </div>
          </div>
          <div className="flex items-center justify-center w-9 h-9 rounded-full bg-sky-100 text-sky-700 font-semibold text-sm">
            {(targetName || 'U').charAt(0).toUpperCase()}
          </div>
        </div>
        <div className="flex-1 grid grid-cols-2 gap-2 p-3 bg-sky-50">
          {localStream && (
            <div className="relative border border-sky-100 rounded-2xl overflow-hidden bg-black">
              <VideoTile stream={localStream} muted={true} />
              <div className="absolute bottom-2 left-2 text-xs px-2 py-1 rounded-full bg-black/60 text-white">You</div>
            </div>
          )}
          {remoteStreams.map(rs => (
            <div key={rs.userId} className="relative border border-sky-100 rounded-2xl overflow-hidden bg-black">
              <VideoTile stream={rs.stream} muted={false} />
              <div className="absolute bottom-2 left-2 text-xs px-2 py-1 rounded-full bg-black/60 text-white">{getNameForUser(rs.userId)}</div>
            </div>
          ))}
          {!localStream && remoteStreams.length === 0 && (
            <div className="col-span-2 flex flex-col items-center justify-center text-gray-600 text-sm">
              <div className="w-16 h-16 rounded-full bg-sky-100 text-sky-700 flex items-center justify-center text-2xl font-semibold mb-3">
                {(targetName || 'U').charAt(0).toUpperCase()}
              </div>
              <div className="text-base font-semibold mb-1">{targetName}</div>
              <div className="text-xs text-gray-400">Calling… waiting for media to connect</div>
            </div>
          )}
        </div>
        <div className="py-3 flex items-center justify-center gap-4 bg-white border-t border-gray-100">
          <button
            onClick={onEnd}
            className="w-12 h-12 rounded-full bg-red-600 hover:bg-red-700 flex items-center justify-center text-white text-lg"
          >
            <span className="material-icons">call_end</span>
          </button>
        </div>
      </div>
    </div>
  )
}

function IncomingCallModal({ call, onAccept, onReject, conversations }) {
  const conversation = conversations?.find(c => c._id === call.conversationId)
  const isGroup = conversation?.type === 'group'
  const displayName = isGroup
    ? (conversation?.name || 'Group')
    : (call.from?.username || 'Unknown user')
  const callType = call.kind === 'video' ? 'video' : 'voice'

  return (
    <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center">
      <div className="w-[320px] bg-white rounded-2xl shadow-xl p-5">
        <div className="text-sm text-gray-500 mb-1">Incoming {callType} call</div>
        <div className="text-lg font-semibold mb-4">
          {isGroup ? `Call from ${displayName}` : displayName}
        </div>
        <div className="flex items-center justify-between gap-3">
          <button
            onClick={onReject}
            className="flex-1 py-2 rounded-full bg-gray-200 text-gray-800 text-sm"
          >
            Decline
          </button>
          <button
            onClick={onAccept}
            className="flex-1 py-2 rounded-full bg-primary text-white text-sm"
          >
            Accept
          </button>
        </div>
      </div>
    </div>
  )
}

function MembersModal({ conv, onClose }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [members, setMembers] = useState([])
  const [showAddMember, setShowAddMember] = useState(false)
  const { token, user } = useStore()

  const fetchMembers = async () => {
    if (!conv?._id) return

    try {
      setLoading(true)
      setError(null)

      // Fetch fresh conversation data to ensure we have the latest members
      const r = await fetch(`${API}/api/conversations/${conv._id}`, {
        headers: { Authorization: `Bearer ${token}` }
      })

      if (!r.ok) {
        throw new Error('Failed to fetch group members')
      }

      const data = await r.json()
      if (data.members && Array.isArray(data.members)) {
        setMembers(data.members)
      } else {
        setMembers(conv.members || [])
      }
    } catch (err) {
      console.error('Error fetching members:', err)
      setError(err.message || 'Failed to load group members')
      setMembers(conv.members || [])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchMembers()
  }, [conv?._id, token])

  const isAdmin = members.length > 0 && String(members[0]._id) === String(user?._id)

  if (!conv) {
    return (
      <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50">
        <div className="w-[480px] bg-white rounded-2xl shadow-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="font-semibold text-lg">Group Members</div>
            <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div className="text-center py-6 text-gray-500">
            No conversation selected
          </div>
        </div>
      </div>
    )
  }

  return (
    <>
      <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50" onClick={onClose}>
        <div className="w-[90%] max-w-md bg-white rounded-2xl shadow-xl p-6" onClick={e => e.stopPropagation()}>
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="font-semibold text-lg">Group Members</div>
              <div className="text-xs text-gray-500">{conv.name || 'Group Chat'}</div>
            </div>
            <button
              onClick={onClose}
              className="text-gray-500 hover:text-gray-700 p-1 -mr-1"
              aria-label="Close"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {loading ? (
            <div className="flex justify-center py-8">
              <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
            </div>
          ) : error ? (
            <div className="bg-red-50 text-red-700 p-3 rounded-lg text-sm mb-4">
              {error}
            </div>
          ) : members.length === 0 ? (
            <div className="text-center py-6 text-gray-500">
              No members in this group
            </div>
          ) : (
            <div className="space-y-2 max-h-[60vh] overflow-y-auto pr-2 -mr-2">
              {members.map(member => (
                <div
                  key={member._id}
                  className="flex items-center gap-3 bg-sky-50/60 hover:bg-sky-100/60 rounded-xl p-3 transition-colors group"
                >
                  <div className="w-10 h-10 rounded-full bg-indigo-100 text-indigo-700 grid place-items-center font-semibold text-lg flex-shrink-0">
                    {member.username?.charAt(0)?.toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="font-medium text-sm truncate">
                      {member.username}
                      {member._id === conv.members[0]?._id && (
                        <span className="ml-2 text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full">
                          Admin
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-gray-500">
                      {member.email || 'No email'}
                    </div>
                  </div>

                  {isAdmin && String(member._id) !== String(user?._id) && (
                    <button
                      onClick={async (e) => {
                        e.stopPropagation()
                        if (!confirm(`Remove ${member.username} from group?`)) return
                        try {
                          // First verify the conversation exists and user is admin
                          const verifyRes = await fetch(`${API}/api/conversations/${conv._id}`, {
                            headers: { Authorization: `Bearer ${token}` }
                          });

                          if (!verifyRes.ok) {
                            throw new Error(verifyRes.status === 404 ? 'Conversation not found' : 'Failed to verify conversation');
                          }

                          const convData = await verifyRes.json();
                          const isAdmin = convData.members.length > 0 && String(convData.members[0]._id) === String(user?._id);

                          if (!isAdmin) {
                            throw new Error('Only group admin can remove members');
                          }

                          // Now make the remove member request
                          const r = await fetch(`${API}/api/conversations/${conv._id}/remove-member`, {
                            method: 'POST',
                            headers: {
                              'Content-Type': 'application/json',
                              Authorization: `Bearer ${token}`
                            },
                            body: JSON.stringify({ userId: member._id })
                          });

                          const responseData = await r.json().catch(() => ({}));

                          if (r.ok) {
                            fetchMembers(); // Refresh list
                          } else {
                            throw new Error(responseData.error || `Failed to remove member: ${r.status} ${r.statusText}`);
                          }
                        } catch (err) {
                          console.error('Remove member error:', err);
                          alert(`Error removing member: ${err.message}`);
                        }
                      }}
                      className="text-red-500 hover:text-red-700 text-xs px-2 py-1 rounded hover:bg-red-50 opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      Remove
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}

          <div className="mt-6 pt-4 border-t space-y-2">
            <button
              onClick={() => setShowAddMember(true)}
              className="w-full bg-green-500 text-white py-2 px-4 rounded-lg hover:bg-green-600 transition-colors"
            >
              + Add New User
            </button>
            <button
              onClick={onClose}
              className="w-full bg-primary text-white py-2 px-4 rounded-lg hover:bg-primary/90 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>

      {showAddMember && (
        <AddMemberModal
          conversationId={conv._id}
          token={token}
          existingMembers={members}
          onClose={() => setShowAddMember(false)}
          onSuccess={() => {
            fetchMembers()
            // Optional: Show a toast or alert
            alert('Member added successfully!')
          }}
        />
      )}
    </>
  )
}

function MessageInfoModal({ message, conv, onClose }) {
  if (!message) return null

  const members = Array.isArray(conv?.members) ? conv.members : []
  const byIds = (ids = []) => {
    if (!Array.isArray(ids)) return [];
    return members.filter(u => ids.map(String).includes(String(u._id)))
  }

  const sender = message.sender?.username ||
    members.find(m => String(m._id) === String(message.sender))?.username ||
    'Unknown'
  const senderId = String(message.sender?._id || message.sender)

  // Filter out the sender from seen/delivered lists
  const seenBy = byIds(message.seenBy || []).filter(u => String(u._id) !== senderId)
  const deliveredTo = byIds(message.deliveredTo || []).filter(u => String(u._id) !== senderId)
  const isGroup = conv?.type === 'group'

  // Calculate total recipients (excluding sender)
  const totalRecipients = members.filter(m => String(m._id) !== senderId).length

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50" onClick={onClose}>
      <div className="w-[90%] max-w-md bg-white rounded-2xl shadow-xl p-6" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <div className="font-semibold text-lg">Message Information</div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="space-y-4 text-sm">
          <div className="p-3 bg-gray-50 rounded-lg">
            <div className="text-gray-500 text-xs mb-1">Message</div>
            <div className="whitespace-pre-wrap break-words">{message.content}</div>
          </div>

          <div className="space-y-3">
            <div>
              <div className="text-gray-500 text-xs mb-1">Sent by</div>
              <div className="font-medium">{sender}</div>
              <div className="text-xs text-gray-500">
                {dayjs(message.createdAt).format('MMM D, YYYY h:mm A')}
              </div>
            </div>

            {isGroup && (
              <>
                <div className="border-t my-2"></div>

                <div>
                  <div className="text-gray-500 text-xs mb-2">
                    Read by {seenBy.length} of {totalRecipients}
                  </div>
                  {seenBy.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {seenBy.map(u => (
                        <div key={u._id} className="px-2 py-1 bg-green-50 text-green-700 text-xs rounded-full flex items-center gap-1">
                          <span>✓✓</span>
                          <span>{u.username}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-gray-400 text-sm">Not read yet</span>
                  )}
                </div>


              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function Chat() {
  const { token, setToken, user, setUser, conversations, setConversations, activeId, setActiveId, messages, setMessages, pushMessage, updateMessage, replaceTempMessage, removeMessage, logout, profileOpen, setProfileOpen } = useStore()
  console.log('Chat Component Rendered. User:', user);
  const [socket, setSocket] = useState(null)
  const [typingUsers, setTypingUsers] = useState({})
  const [openNew, setOpenNew] = useState(false)
  const [selectedMessages, setSelectedMessages] = useState(new Set())
  const [toast, setToast] = useState(null)
  const nav = useNavigate()
  const [showMembers, setShowMembers] = useState(false)
  const [infoMsg, setInfoMsg] = useState(null)
  const [incomingCall, setIncomingCall] = useState(null)
  const [currentCall, setCurrentCall] = useState(null)
  const [localStream, setLocalStream] = useState(null)
  const [remoteStreams, setRemoteStreams] = useState([])
  const peerConnectionsRef = useRef(new Map())
  const localStreamRef = useRef(null)
  const socketRef = useRef(null)
  const currentCallRef = useRef(null)
  const remoteStreamCleanupsRef = useRef(new Map())
  const [isMicOn, setIsMicOn] = useState(true)
  const [isCameraOn, setIsCameraOn] = useState(true)
  const [isScreenSharing, setIsScreenSharing] = useState(false)
  const [participantStates, setParticipantStates] = useState({})

  const handleSaveEdit = async () => {
    if (!editingMessageId || !editingMessageContent.trim()) return

    try {
      const res = await fetch(`${API}/api/messages/${editingMessageId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ content: editingMessageContent })
      })
      if (res.ok) {
        useStore.getState().updateMessage(activeId, editingMessageId, { content: editingMessageContent, editedAt: new Date().toISOString() })
        setEditingMessageId(null)
        setEditingMessageContent('')
      } else {
        alert('Failed to edit message')
      }
    } catch (e) {
      console.error('Error editing message:', e)
      alert('Failed to edit message')
    }
  }

  const handleCancelEdit = () => {
    setEditingMessageId(null)
    setEditingMessageContent('')
  }

  // Top search state
  const [topSearchQuery, setTopSearchQuery] = useState('')
  const [topSearchResults, setTopSearchResults] = useState([])
  const [showTopSearch, setShowTopSearch] = useState(false)

  const removeRemotePeer = (peerId) => {
    if (!peerId) return
    const key = String(peerId)

    const cleanup = remoteStreamCleanupsRef.current.get(key)
    if (cleanup) {
      try { cleanup() } catch (err) { console.warn('Remote stream cleanup failed', err) }
      remoteStreamCleanupsRef.current.delete(key)
    }

    const pc = peerConnectionsRef.current.get(key)
    if (pc) {
      try {
        pc.ontrack = null
        pc.onicecandidate = null
        pc.onnegotiationneeded = null
        pc.onconnectionstatechange = null
        pc.close()
      } catch (err) {
        console.warn('Peer connection close failed', err)
      }
      peerConnectionsRef.current.delete(key)
    }

    setRemoteStreams(prev => prev.filter(s => String(s.userId) !== key))
  }

  const registerRemoteStream = (peerId, stream) => {
    if (!peerId || !stream) return
    const key = String(peerId)

    // Remove previous listeners if we already had a stream for this peer
    const existingCleanup = remoteStreamCleanupsRef.current.get(key)
    if (existingCleanup) {
      try { existingCleanup() } catch (err) { console.warn('Cleanup removal failed', err) }
    }

    const handleTrackEnded = () => {
      const tracks = stream.getTracks()
      const allEnded = tracks.length === 0 || tracks.every(track => track.readyState === 'ended')
      if (allEnded) {
        removeRemotePeer(key)
      }
    }

    stream.getTracks().forEach(track => {
      track.addEventListener('ended', handleTrackEnded)
    })

    remoteStreamCleanupsRef.current.set(key, () => {
      stream.getTracks().forEach(track => {
        track.removeEventListener('ended', handleTrackEnded)
      })
    })
  }

  useEffect(() => {
    currentCallRef.current = currentCall
  }, [currentCall])

  useEffect(() => {
    const saved = localStorage.getItem('token')
    if (saved) setToken(saved)
  }, [])

  // Force macOS (and browsers) to ask for microphone permission once
  useEffect(() => {
    if (!navigator.mediaDevices?.getUserMedia) return
    navigator.mediaDevices.getUserMedia({ audio: true })
      .then((stream) => {
        console.log('Microphone allowed')
        // We only needed permission; stop tracks immediately
        stream.getTracks().forEach(t => t.stop())
      })
      .catch((err) => {
        console.error('Microphone denied', err)
      })
  }, [])

  // Top search logic
  useEffect(() => {
    if (!user || !topSearchQuery.trim()) {
      setTopSearchResults([])
      setShowTopSearch(false)
      return
    }
    const timer = setTimeout(async () => {
      try {
        const r = await fetch(`${API}/api/users`)
        const list = await r.json()
        const lower = topSearchQuery.toLowerCase()
        const matches = list.filter(u =>
          String(u._id) !== String(user._id) && (
            u.username.toLowerCase().includes(lower) ||
            (u.email && u.email.toLowerCase().includes(lower))
          )
        ).slice(0, 5)
        setTopSearchResults(matches)
        setShowTopSearch(true)
      } catch (e) {
        console.error(e)
      }
    }, 300)
    return () => clearTimeout(timer)
  }, [topSearchQuery, user?._id])

  useEffect(() => {
    (async () => {
      if (!token) return
      // validate token and get user
      try {
        const meRes = await fetch(`${API}/api/auth/me`, {
          method: 'GET',
          headers: { Authorization: `Bearer ${token}` },
          cache: 'no-store',
        })

        if (!meRes.ok) { logout(); return }
        const me = await meRes.json()
        setUser(me)
        setProfileOpen(false)
      } catch (e) {
        console.error('Failed to load current user', e)
        logout()
        return
      }
      const s = createSocket(token)
      setSocket(s)
      socketRef.current = s

      s.on('message_new', (msg) => {
        const convId = String(msg.conversation?._id || msg.conversation)
        const state = useStore.getState()
        const myId = state.user?._id ? String(state.user._id) : ''
        const senderId = String(msg.sender?._id || msg.sender)

        if (senderId === myId && msg.tempId) {
          replaceTempMessage(convId, msg.tempId, msg)
        } else {
          pushMessage(convId, msg)
        }

        // Check if conversation exists in state, if not fetch it (it might have been hidden/deleted)
        const conversationExists = state.conversations.some(c => c._id === convId)
        if (!conversationExists) {
          fetch(`${API}/api/conversations/${convId}`, {
            headers: { Authorization: `Bearer ${token}` }
          })
            .then(r => r.ok ? r.json() : null)
            .then(newConv => {
              if (newConv) {
                setConversations(prev => {
                  // Double check to avoid duplicates
                  if (prev.find(c => c._id === newConv._id)) return prev
                  return [newConv, ...prev]
                })
                // Join the room if not already joined (though socket.on('conversation_created') handles this usually, 
                // but for reappearing chats we might need it)
                s.emit('join_conversation', convId)
              }
            })
            .catch(console.error)
        }

        // Update lastMessageAt so lists can sort by recent activity
        setConversations(cs => cs.map(c => c._id === convId ? { ...c, lastMessageAt: msg.createdAt || c.lastMessageAt || new Date().toISOString() } : c))

        const isFromMe = senderId === myId
        const isActive = String(state.activeId || '') === convId

        console.log('message_new', msg._id, 'conv:', convId, 'fromMe:', isFromMe, 'active:', isActive)

        // Increment unread count if message is not from me and conversation is not active
        if (!isFromMe && !isActive) {
          console.log('Incrementing unread for', convId)
          state.incrementUnread?.(convId)
          const conv = (state.conversations || []).find(c => String(c._id) === convId)
          const other = conv?.type === 'group'
            ? null
            : (conv?.members || []).find(m => String(m._id) !== myId)
          const title = conv
            ? (conv.type === 'group'
              ? (conv.name || 'Group')
              : (other?.username || 'Direct'))
            : 'New message'
          state.pushNotification?.({
            id: String(msg._id || msg.tempId || `${convId}-${Date.now()}`),
            conversationId: convId,
            title,
            message: msg.content,
            from: msg.sender?.username || other?.username || 'Someone',
            createdAt: msg.createdAt,
          })
        }

        if (!isFromMe) {
          s.emit('message_delivered', { messageId: msg._id })
        }
      })
      s.on('message_update', ({ messageId, deliveredTo, seenBy }) => {
        console.log('message_update', messageId, deliveredTo?.length, seenBy?.length)
        const state = useStore.getState()
        const convId = Object.keys(state.messages).find(cid => (state.messages[cid] || []).some(m => m._id === messageId))
        if (convId) state.updateMessage(convId, messageId, { deliveredTo, seenBy })
      })
      s.on('message_edited', ({ messageId, content, editedAt }) => {
        const state = useStore.getState()
        const convId = Object.keys(state.messages).find(cid => (state.messages[cid] || []).some(m => m._id === messageId))
        if (convId) state.updateMessage(convId, messageId, { content, editedAt })
      })
      s.on('message_deleted', ({ messageId, conversationId }) => {
        removeMessage(conversationId, messageId)
        setSelectedMessages(prev => {
          const next = new Set(prev)
          next.delete(messageId)
          return next
        })
      })
      s.on('typing', ({ conversationId, userId }) => {
        setTypingUsers(t => ({ ...t, [conversationId]: new Set([...(t[conversationId] || []), userId]) }))
      })
      s.on('stop_typing', ({ conversationId, userId }) => {
        setTypingUsers(t => {
          const setUsers = new Set(t[conversationId] || [])
          setUsers.delete(userId)
          return { ...t, [conversationId]: setUsers }
        })
      })

      s.on('user_online', ({ userId, lastSeenAt }) => {
        setConversations(convs => convs.map(conv => ({
          ...conv,
          members: conv.members?.map(m =>
            String(m._id) === String(userId) ? { ...m, lastSeenAt } : m
          )
        })))
      })

      s.on('user_offline', ({ userId, lastSeenAt }) => {
        setConversations(convs => convs.map(conv => ({
          ...conv,
          members: conv.members?.map(m =>
            String(m._id) === String(userId) ? { ...m, lastSeenAt } : m
          )
        })))
      })

      // Listen for new conversations created by other users
      s.on('conversation_created', async (conversation) => {
        console.log('New conversation created:', conversation)
        // Add the new conversation to the list if not already present
        setConversations(cs => {
          const exists = cs.find(c => c._id === conversation._id)
          if (exists) return cs
          // Join the conversation room
          s.emit('join_conversation', conversation._id)
          return [conversation, ...cs]
        })
      })

      // Listen for conversation deletions
      s.on('conversation_deleted', ({ conversationId }) => {
        console.log('Conversation deleted:', conversationId)
        setConversations(cs => cs.filter(c => c._id !== conversationId))
        // If the deleted conversation was active, clear it
        if (activeId === conversationId) {
          setActiveId(null)
        }
      })

      s.on('call_incoming', (payload) => {
        if (!payload) return
        if (currentCallRef.current) return
        setIncomingCall(payload)
      })

      s.on('call_started', async (payload) => {
        if (!payload) return
        currentCallRef.current = payload
        setCurrentCall(payload)
        setIsMicOn(true)
        setIsCameraOn(payload.kind === 'video')
        setIsScreenSharing(false)
        await ensureLocalStream(payload.kind)
      })

      s.on('call_existing_participants', async ({ callId, conversationId, userIds }) => {
        if (!callId || !Array.isArray(userIds) || !user?._id) return
        const call = currentCallRef.current || { callId, conversationId, kind: 'audio' }
        await ensureLocalStream(call.kind)
        const myId = String(user._id)
        console.log(`Existing participants for call ${callId}:`, userIds)
        for (const uid of userIds) {
          const peerId = String(uid)
          if (peerId === myId) continue
          // Just ensure the peer connection exists; negotiationneeded
          // will fire and create an offer when the connection is stable.
          const pc = getOrCreatePeerConnection(callId, peerId)
          // Trigger negotiation if we have tracks and are in stable state
          if (pc.signalingState === 'stable' && localStreamRef.current) {
            setTimeout(() => {
              if (pc.onnegotiationneeded) {
                pc.onnegotiationneeded()
              }
            }, 100)
          }
        }
      })

      s.on('call_peer_accepted', async ({ callId, conversationId, userId }) => {
        if (!callId || !userId || !user?._id) return
        const myId = String(user._id)
        if (String(userId) === myId) return
        const call = currentCallRef.current || { callId, conversationId, kind: 'audio' }
        await ensureLocalStream(call.kind)
        const peerId = String(userId)
        console.log(`Peer ${peerId} accepted call ${callId}`)
        const pc = getOrCreatePeerConnection(callId, peerId)
        // Trigger negotiation if we have tracks and are in stable state
        if (pc.signalingState === 'stable' && localStreamRef.current) {
          setTimeout(() => {
            if (pc.onnegotiationneeded) {
              pc.onnegotiationneeded()
            }
          }, 100)
        }
      })

      s.on('call_signal', async ({ callId, fromUserId, data }) => {
        if (!callId || !fromUserId || !data) return
        const peerId = String(fromUserId)
        const call = currentCallRef.current || { callId, kind: 'audio' }
        if (!call) return
        await ensureLocalStream(call.kind)
        const pc = getOrCreatePeerConnection(callId, peerId)

        // Access the ICE candidate queue from the peer connection
        const iceQueue = pc._iceCandidateQueue || []

        try {
          if (data.type === 'offer' && data.sdp) {
            console.log(`Received offer from ${peerId}, current state: ${pc.signalingState}`)
            // Handle remote offer; avoid invalid state transitions
            if (pc.signalingState === 'closed') {
              console.warn(`Cannot handle offer, connection closed for ${peerId}`)
              return
            }

            if (pc.signalingState === 'have-local-offer') {
              console.log(`Rolling back local offer for ${peerId} to handle remote offer`)
              try {
                await pc.setLocalDescription({ type: 'rollback' })
              } catch (e) {
                console.warn('Rollback failed, ignoring conflicting offer', e)
                return
              }
            }

            if (pc.signalingState !== 'stable' && pc.signalingState !== 'have-remote-offer') {
              console.warn(`Unexpected signaling state ${pc.signalingState} for offer from ${peerId}`)
              return
            }

            await pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: data.sdp }))
            console.log(`Set remote description (offer) for ${peerId}, new state: ${pc.signalingState}`)

            // Flush any queued ICE candidates
            if (pc._flushIceCandidates) {
              await pc._flushIceCandidates()
            }

            if (pc.signalingState !== 'have-remote-offer') {
              console.warn(`Unexpected state after setRemoteDescription: ${pc.signalingState}`)
              return
            }

            const answer = await pc.createAnswer()
            await pc.setLocalDescription(answer)
            console.log(`Created and set answer for ${peerId}`)
            if (socketRef.current) {
              socketRef.current.emit('call_signal', {
                callId,
                toUserId: peerId,
                data: { type: 'answer', sdp: answer.sdp },
              })
            }
          } else if (data.type === 'answer' && data.sdp) {
            console.log(`Received answer from ${peerId}, current state: ${pc.signalingState}`)
            // Only set answer if we're in the right state
            if (pc.signalingState === 'closed') {
              console.warn(`Cannot handle answer, connection closed for ${peerId}`)
              return
            }
            if (pc.signalingState !== 'have-local-offer') {
              console.warn(`Unexpected state ${pc.signalingState} for answer from ${peerId}`)
              return
            }
            try {
              await pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: data.sdp }))
              console.log(`Set remote description (answer) for ${peerId}, new state: ${pc.signalingState}`)

              // Flush any queued ICE candidates
              if (pc._flushIceCandidates) {
                await pc._flushIceCandidates()
              }
            } catch (e) {
              // Handle SSL role conflict - this can happen if both sides sent offers
              if (e.name === 'InvalidAccessError' && e.message.includes('SSL role')) {
                console.warn(`SSL role conflict for ${peerId}, will retry negotiation`)
                // The connection will renegotiate via onnegotiationneeded
                return
              }
              throw e
            }
          } else if (data.candidate) {
            try {
              if (pc.remoteDescription) {
                await pc.addIceCandidate(new RTCIceCandidate(data.candidate))
                console.log(`Added ICE candidate from ${peerId}`)
              } else {
                // Queue the candidate if remote description isn't ready
                if (!pc._iceCandidateQueue) {
                  pc._iceCandidateQueue = []
                }
                pc._iceCandidateQueue.push(data.candidate)
                console.log(`Queued ICE candidate from ${peerId} (waiting for remote description)`)
              }
            } catch (e) {
              console.warn('Error adding ICE candidate:', e)
            }
          }
        } catch (e) {
          console.error('Error handling call signal:', e)
        }
      })

      s.on('call_ended', () => {
        cleanupCall()
      })

      s.on('call_user_left', ({ callId, userId }) => {
        if (currentCallRef.current?.callId !== callId) return
        removeRemotePeer(userId)
        // Remove from participant states
        setParticipantStates(prev => {
          const next = { ...prev }
          delete next[userId]
          return next
        })
      })

      s.on('call_participant_state', ({ callId, userId, isMicOff, isCameraOff }) => {
        if (currentCallRef.current?.callId !== callId) return
        setParticipantStates(prev => ({
          ...prev,
          [userId]: { isMicOff, isCameraOff }
        }))
      })

      try {
        const res = await fetch(`${API}/api/conversations`, {
          method: 'GET',
          headers: { Authorization: `Bearer ${token}` },
          cache: 'no-store',
        })

        if (res.status === 304) {
          return
        }

        if (!res.ok) {
          throw new Error(`Failed to load conversations: ${res.status}`)
        }

        const cs = await res.json()
        const filtered = cs.filter(c => !(c.type === 'group' && String(c.name || '').trim().toLowerCase() === 'lobby'))
        setConversations(filtered)

        // Initialize unread counts
        const unreadMap = {}
        filtered.forEach(c => {
          if (c.unreadCount > 0) {
            unreadMap[c._id] = c.unreadCount
          }
          s.emit('join_conversation', c._id)
        })
        useStore.setState({ unreadCounts: unreadMap })
        setActiveId(null)
      } catch (e) {
        console.error('Failed to load conversations', e)
      }
    })()
  }, [token])

  useEffect(() => {
    if (!socket || !activeId || !user || !token) return
    socket.emit('join_conversation', activeId)

      ; (async () => {
        const r = await fetch(`${API}/api/messages/${activeId}`, { headers: { Authorization: `Bearer ${token}` } })
        const msgs = await r.json()
        setMessages(activeId, msgs)
        socket.emit('message_seen', { conversationId: activeId })
      })()
    return () => socket.emit('leave_conversation', activeId)
  }, [socket, activeId, token])

  useEffect(() => {
    const unsub = useStore.subscribe((state) => state.notifications, (notifs, prev) => {
      if (notifs && prev && notifs.length > prev.length) {
        setToast(notifs[0])
      }
    })
    return () => unsub()
  }, [])

  if (!token) return null
  if (!user) return <div className="h-screen grid place-items-center text-gray-600">Loading...</div>

  const onLogout = () => { logout(); nav('/login') }

  const getDeletedForMeMap = () => {
    try { return JSON.parse(localStorage.getItem('deletedForMe') || '{}') } catch { return {} }
  }
  const setDeletedForMeMap = (map) => {
    try { localStorage.setItem('deletedForMe', JSON.stringify(map)) } catch {}
  }
  const addDeletedForMe = (convId, ids) => {
    const map = getDeletedForMeMap()
    const existing = new Set((map[convId] || []).map(String))
    ids.forEach(id => existing.add(String(id)))
    map[convId] = [...existing]
    setDeletedForMeMap(map)
  }
  const getDeletedIdsForConv = (convId) => new Set(((getDeletedForMeMap()[convId]) || []).map(String))

  const refreshMessages = async () => {
    if (!socket || !activeId || !user || !token) return
    const r = await fetch(`${API}/api/messages/${activeId}`, { headers: { Authorization: `Bearer ${token}` } })
    const msgs = await r.json()
    const hidden = getDeletedIdsForConv(activeId)
    const filtered = (msgs || []).filter(m => !hidden.has(String(m._id)))
    setMessages(activeId, filtered)
  }

  async function ensureLocalStream(kind) {
    if (localStreamRef.current) return localStreamRef.current
    try {
      const constraints = kind === 'video'
        ? {
          audio: {
            echoCancellation: true,
            noiseSuppression: true,
            autoGainControl: true
          },
          video: { width: 640, height: 480 }
        }
        : {
          audio: {
            echoCancellation: true,
            noiseSuppression: true,
            autoGainControl: true
          },
          video: false
        }
      const stream = await navigator.mediaDevices.getUserMedia(constraints)

      // Ensure audio tracks are enabled
      stream.getAudioTracks().forEach(track => {
        track.enabled = true
      })

      console.log('Local stream created', {
        audioTracks: stream.getAudioTracks().length,
        videoTracks: stream.getVideoTracks().length,
        kind,
      })

      localStreamRef.current = stream
      setLocalStream(stream)
      return stream
    } catch (e) {
      console.error('Error getting user media:', e)
      return null
    }
  }

  function cleanupCall() {
    peerConnectionsRef.current.forEach((pc) => {
      try { pc.close() } catch (e) { }
    })
    peerConnectionsRef.current.clear()
    remoteStreamCleanupsRef.current.forEach((cleanup) => {
      try { cleanup() } catch (err) { console.warn('Remote stream detach failed', err) }
    })
    remoteStreamCleanupsRef.current.clear()
    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach(t => t.stop())
      localStreamRef.current = null
    }
    setLocalStream(null)
    setRemoteStreams([])
    setCurrentCall(null)
    setIncomingCall(null)
    currentCallRef.current = null
    setIsMicOn(true)
    setIsCameraOn(true)
    setIsScreenSharing(false)
  }

  function getOrCreatePeerConnection(callId, peerUserId) {
    const key = String(peerUserId)
    let pc = peerConnectionsRef.current.get(key)
    if (pc) return pc

    pc = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun3.l.google.com:19302' },
        { urls: 'stun:stun4.l.google.com:19302' },
        { urls: 'stun:global.stun.twilio.com:3478' }
      ],
      iceCandidatePoolSize: 10
    })
    peerConnectionsRef.current.set(key, pc)

    // Queue for ICE candidates that arrive before remote description
    const iceCandidateQueue = []
    const flushIceCandidates = async () => {
      if (!pc.remoteDescription) return
      while (iceCandidateQueue.length > 0) {
        const candidate = iceCandidateQueue.shift()
        try {
          await pc.addIceCandidate(new RTCIceCandidate(candidate))
          console.log(`Queued ICE candidate added for ${key}`)
        } catch (e) {
          console.warn('Error adding queued ICE candidate:', e)
        }
      }
    }

    // Store queue and flush function on the peer connection for access in signal handler
    pc._iceCandidateQueue = iceCandidateQueue
    pc._flushIceCandidates = flushIceCandidates

    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach(track => {
        pc.addTrack(track, localStreamRef.current)
      })
    } else {
      if (pc.getTransceivers().length === 0) {
        try { pc.addTransceiver('audio', { direction: 'recvonly' }) } catch (e) { }
        try { pc.addTransceiver('video', { direction: 'recvonly' }) } catch (e) { }
      }
    }

    pc.ontrack = (event) => {
      const stream = event.streams?.[0] || (event.track ? new MediaStream([event.track]) : null)
      if (!stream) return
      stream.getAudioTracks().forEach(track => { track.enabled = true })
      stream.getVideoTracks().forEach(track => { track.enabled = true })
      console.log('Received remote stream from', key, 'audioTracks=', stream.getAudioTracks().length, 'videoTracks=', stream.getVideoTracks().length)
      const uid = key
      setRemoteStreams(prev => {
        const existing = prev.find(x => x.userId === uid)
        if (existing && existing.stream === stream) return prev
        const others = prev.filter(x => x.userId !== uid)
        return [...others, { userId: uid, stream }]
      })
      registerRemoteStream(uid, stream)
    }

    pc.onicecandidate = (event) => {
      if (event.candidate && socketRef.current) {
        console.log(`ICE candidate for ${key}:`, event.candidate.candidate.substring(0, 50))
        socketRef.current.emit('call_signal', {
          callId,
          toUserId: key,
          data: { candidate: event.candidate }
        })
      } else if (!event.candidate) {
        console.log(`ICE gathering complete for ${key}`)
      }
    }

    pc.onicegatheringstatechange = () => {
      console.log(`ICE gathering state for ${key}:`, pc.iceGatheringState)
    }

    let iceDisconnectTimeout = null
    let iceRestartAttempts = 0
    const MAX_ICE_RESTARTS = 3

    const schedulePeerRemoval = (delayMs) => {
      if (iceDisconnectTimeout) return
      iceDisconnectTimeout = setTimeout(() => {
        iceDisconnectTimeout = null
        console.log(`Removing peer ${key} after connection failure`)
        removeRemotePeer(key)
      }, delayMs)
    }

    pc.oniceconnectionstatechange = () => {
      const state = pc.iceConnectionState
      console.log(`ICE connection state for ${key}:`, state)
      if (state === 'failed') {
        if (iceRestartAttempts < MAX_ICE_RESTARTS) {
          iceRestartAttempts++
          console.log(`ICE connection failed, attempting restart (${iceRestartAttempts}/${MAX_ICE_RESTARTS})`)
          try {
            pc.restartIce()
            // Give it more time after restart
            if (iceDisconnectTimeout) {
              clearTimeout(iceDisconnectTimeout)
              iceDisconnectTimeout = null
            }
          } catch (err) {
            console.warn('ICE restart error:', err)
            schedulePeerRemoval(4000)
          }
        } else {
          console.error(`ICE connection failed after ${MAX_ICE_RESTARTS} restart attempts for ${key}`)
          schedulePeerRemoval(2000)
        }
      } else if (state === 'disconnected') {
        console.log(`ICE disconnected for ${key}, waiting for reconnection...`)
        schedulePeerRemoval(8000) // Give more time for reconnection
      } else if (state === 'checking') {
        console.log(`ICE checking for ${key}`)
        // Cancel any pending removal when we start checking again
        if (iceDisconnectTimeout) {
          clearTimeout(iceDisconnectTimeout)
          iceDisconnectTimeout = null
        }
        iceRestartAttempts = 0 // Reset on new check
      } else if (state === 'connected' || state === 'completed') {
        console.log(`ICE connected/completed for ${key}`)
        if (iceDisconnectTimeout) {
          clearTimeout(iceDisconnectTimeout)
          iceDisconnectTimeout = null
        }
        iceRestartAttempts = 0
      }
    }

    pc.onconnectionstatechange = () => {
      const state = pc.connectionState
      console.log(`Peer ${key} connection state:`, state)
      if (state === 'closed') {
        console.log(`Peer connection closed for ${key}`)
        removeRemotePeer(key)
      } else if (state === 'failed') {
        console.error(`Peer connection failed for ${key}`)
        // Try ICE restart before removing
        if (pc.iceConnectionState !== 'closed') {
          try {
            pc.restartIce()
            setTimeout(() => {
              if (pc.connectionState === 'failed') {
                removeRemotePeer(key)
              }
            }, 5000)
          } catch (e) {
            removeRemotePeer(key)
          }
        } else {
          removeRemotePeer(key)
        }
      } else if (state === 'connected') {
        console.log(`Peer connection established for ${key}`)
        if (iceDisconnectTimeout) {
          clearTimeout(iceDisconnectTimeout)
          iceDisconnectTimeout = null
        }
      }
    }

    // Controlled negotiation to avoid offer glare and invalid states
    let isNegotiating = false
    let negotiationTimeout = null

    const attemptNegotiation = async () => {
      if (isNegotiating) return
      isNegotiating = true

      const call = currentCallRef.current
      if (!call || !socketRef.current) {
        isNegotiating = false
        return
      }

      // Wait for stable state if not already stable
      if (pc.signalingState !== 'stable') {
        console.log(`Waiting for stable state before negotiation for ${key}, current: ${pc.signalingState}`)
        isNegotiating = false
        // Retry after a short delay
        if (negotiationTimeout) clearTimeout(negotiationTimeout)
        negotiationTimeout = setTimeout(() => {
          if (pc.signalingState === 'stable' && !isNegotiating) {
            attemptNegotiation()
          }
        }, 100)
        return
      }

      try {
        const before = pc.signalingState
        const offer = await pc.createOffer({
          offerToReceiveAudio: true,
          offerToReceiveVideo: call.kind === 'video'
        })

        // If state changed (e.g. we received a remote offer), abort this negotiation
        if (pc.signalingState !== before || pc.signalingState !== 'stable') {
          console.log(`State changed during offer creation for ${key}, aborting`)
          isNegotiating = false
          return
        }

        await pc.setLocalDescription(offer)
        console.log(`Created and sent offer to ${key}`)
        socketRef.current.emit('call_signal', {
          callId: call.callId,
          toUserId: key,
          data: { type: 'offer', sdp: offer.sdp },
        })
      } catch (e) {
        // These errors often happen due to races when both sides negotiate.
        // Treat InvalidStateError / OperationError as benign and ignore.
        if (e && (e.name === 'InvalidStateError' || e.name === 'OperationError')) {
          console.warn('Negotiation race ignored for', key)
        } else {
          console.error('Negotiation error for', key, ':', e)
        }
      } finally {
        isNegotiating = false
      }
    }

    pc.onnegotiationneeded = () => {
      console.log(`Negotiation needed for ${key}, current state: ${pc.signalingState}`)
      attemptNegotiation()
    }

    return pc
  }

  function startCall(kind) {
    if (!socketRef.current || !activeId || !user) return
    const conv = conversations.find(c => c._id === activeId)
    if (!conv) return
    socketRef.current.emit('call_start', { conversationId: activeId, kind })
  }

  async function acceptIncomingCall() {
    if (!incomingCall || !socketRef.current) return
    const call = incomingCall
    setIncomingCall(null)
    currentCallRef.current = call
    setCurrentCall(call)
    await ensureLocalStream(call.kind)
    socketRef.current.emit('call_accept', { callId: call.callId, conversationId: call.conversationId })
  }

  function rejectIncomingCall() {
    if (!incomingCall || !socketRef.current) {
      setIncomingCall(null)
      return
    }
    const call = incomingCall
    socketRef.current.emit('call_end', { callId: call.callId, conversationId: call.conversationId })
    setIncomingCall(null)
    cleanupCall()
  }

  function endCall() {
    if (currentCall && socketRef.current) {
      const conv = conversations.find(c => c._id === currentCall.conversationId)
      if (conv && conv.type === 'group') {
        socketRef.current.emit('call_leave', { callId: currentCall.callId, conversationId: currentCall.conversationId })
      } else {
        socketRef.current.emit('call_end', { callId: currentCall.callId, conversationId: currentCall.conversationId })
      }
    }
    cleanupCall()
  }

  async function toggleMic() {
    const next = !isMicOn
    const stream = localStreamRef.current

    try {
      if (stream) {
        let audioTracks = stream.getAudioTracks()

        if (audioTracks.length === 0 && next) {
          const audioStream = await navigator.mediaDevices.getUserMedia({
            audio: {
              echoCancellation: true,
              noiseSuppression: true,
              autoGainControl: true,
            },
            video: false,
          })

          const audioTrack = audioStream.getAudioTracks()[0]
          if (audioTrack) {
            stream.addTrack(audioTrack)
            peerConnectionsRef.current.forEach(pc => {
              const sender = pc.getSenders().find(s => s.track && s.track.kind === 'audio')
              if (sender) sender.replaceTrack(audioTrack)
              else pc.addTrack(audioTrack, stream)
            })
            audioTracks = [audioTrack]
          }
        }

        audioTracks.forEach(t => {
          t.enabled = next
        })
      }
    } catch (e) {
      console.error('Error toggling mic', e)
    }

    setIsMicOn(next)

    // Broadcast state to other participants
    if (socketRef.current && currentCallRef.current) {
      socketRef.current.emit('call_participant_state', {
        callId: currentCallRef.current.callId,
        isMicOff: !next,
        isCameraOff: !isCameraOn
      })
    }
  }

  async function toggleCamera() {
    const stream = localStreamRef.current
    const turningOn = !isCameraOn

    // No local stream yet: request full AV stream
    if (!stream) {
      if (!turningOn) {
        setIsCameraOn(false)
        return
      }
      try {
        const camStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: { width: 640, height: 480 } })
        localStreamRef.current = camStream
        setLocalStream(camStream)
        setIsCameraOn(true)
        // Attach tracks to all existing peer connections
        peerConnectionsRef.current.forEach(pc => {
          camStream.getTracks().forEach(track => {
            const existingSender = pc.getSenders().find(s => s.track && s.track.kind === track.kind)
            if (existingSender) existingSender.replaceTrack(track)
            else pc.addTrack(track, camStream)
          })
        })
      } catch (e) {
        setIsCameraOn(false)
      }
      return
    }

    const videoTracks = stream.getVideoTracks()

    // If we already have a video track, just toggle enabled state
    if (videoTracks.length > 0) {
      videoTracks.forEach(t => { t.enabled = !isCameraOn })
      setIsCameraOn(!isCameraOn)
      return
    }

    // Audio-only stream and user wants to turn camera on: add a new video track
    if (turningOn) {
      try {
        const camStream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480 } })
        const camTrack = camStream.getVideoTracks()[0]
        if (!camTrack) return

        stream.addTrack(camTrack)
        setLocalStream(new MediaStream(stream.getTracks()))

        peerConnectionsRef.current.forEach(pc => {
          const sender = pc.getSenders().find(s => s.track && s.track.kind === 'video')
          if (sender) sender.replaceTrack(camTrack)
          else pc.addTrack(camTrack, stream)
        })

        setIsCameraOn(true)
      } catch (e) {
        setIsCameraOn(false)
      }
    } else {
      setIsCameraOn(false)
    }

    // Broadcast state to other participants
    if (socketRef.current && currentCallRef.current) {
      socketRef.current.emit('call_participant_state', {
        callId: currentCallRef.current.callId,
        isMicOff: !isMicOn,
        isCameraOff: !turningOn
      })
    }
  }

  async function toggleScreenShare() {
    if (isScreenSharing) {
      // Stop sharing - revert to camera
      try {
        const camStream = await navigator.mediaDevices.getUserMedia({
          video: { width: 640, height: 480 },
          audio: false // Don't request audio again, we already have it
        })
        const camTrack = camStream.getVideoTracks()[0]

        if (localStreamRef.current && camTrack) {
          const oldTrack = localStreamRef.current.getVideoTracks()[0]
          if (oldTrack) {
            localStreamRef.current.removeTrack(oldTrack)
            oldTrack.stop()
          }
          localStreamRef.current.addTrack(camTrack)
          setLocalStream(new MediaStream(localStreamRef.current.getTracks()))

          // Update PeerConnections
          const replacePromises = []
          peerConnectionsRef.current.forEach(pc => {
            const sender = pc.getSenders().find(s => s.track && s.track.kind === 'video')
            if (sender) {
              replacePromises.push(sender.replaceTrack(camTrack))
            }
          })
          await Promise.all(replacePromises)
        }
        setIsScreenSharing(false)
        setIsCameraOn(true)
      } catch (e) {
        console.error('Failed to revert to camera', e)
        setIsScreenSharing(false)
      }
    } else {
      // Start sharing
      try {
        const screenStream = await navigator.mediaDevices.getDisplayMedia({
          video: {
            cursor: 'always'
          },
          audio: false
        })
        const screenTrack = screenStream.getVideoTracks()[0]

        if (!screenTrack) {
          console.error('No screen track available')
          return
        }

        screenTrack.onended = () => {
          // User stopped sharing via browser UI
          toggleScreenShare()
        }

        if (localStreamRef.current) {
          const oldTrack = localStreamRef.current.getVideoTracks()[0]
          if (oldTrack) {
            localStreamRef.current.removeTrack(oldTrack)
            oldTrack.stop()
          }
          localStreamRef.current.addTrack(screenTrack)
          setLocalStream(new MediaStream(localStreamRef.current.getTracks()))

          // Update PeerConnections
          const replacePromises = []
          peerConnectionsRef.current.forEach(pc => {
            const sender = pc.getSenders().find(s => s.track && s.track.kind === 'video')
            if (sender) {
              replacePromises.push(sender.replaceTrack(screenTrack))
            } else {
              pc.addTrack(screenTrack, localStreamRef.current)
            }
          })
          await Promise.all(replacePromises)
        }
        setIsScreenSharing(true)
      } catch (e) {
        console.error('Failed to start screen share', e)
        // User likely cancelled the screen share dialog
      }
    }
  }

  const handleSendMessage = (text, conversationId = null) => {
    const targetConvId = conversationId || activeId
    if (!text.trim() || !socket || !targetConvId) return
    const tempId = Math.random().toString(36).slice(2)
    const msg = { _id: tempId, tempId, conversation: targetConvId, sender: user, content: text, createdAt: new Date().toISOString(), deliveredTo: [], seenBy: [] }
    pushMessage(targetConvId, msg)
    socket.emit('message_send', { conversationId: targetConvId, content: text, tempId })
    socket.emit('stop_typing', { conversationId: targetConvId })
  }

  if (currentCall) {
    return (
      <CallPage
        call={currentCall}
        localStream={localStream}
        remoteStreams={remoteStreams}
        onEnd={endCall}
        onToggleMic={toggleMic}
        onToggleCamera={toggleCamera}
        onShareScreen={toggleScreenShare}
        isMicOn={isMicOn}
        isCameraOn={isCameraOn}
        isScreenSharing={isScreenSharing}
        conversation={conversations.find(c => c._id === currentCall.conversationId)}
        currentUser={user}
        messages={messages[currentCall.conversationId] || []}
        onSendMessage={(text) => handleSendMessage(text, currentCall.conversationId)}
        participantStates={participantStates}
      />
    )
  }

  return (
    <div className="h-screen w-screen p-4">
      <div className="h-12 mb-3 flex items-center justify-between px-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-full bg-yellow-400 grid place-items-center font-bold">💬</div>
          <div className="font-semibold text-lg">XevyTalk</div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2">
            <button className="p-1.5 text-gray-500 hover:bg-gray-100 rounded-full">
              <span className="material-icons">folder</span>
            </button>
            <button className="p-1.5 text-gray-500 hover:bg-gray-100 rounded-full">
              <span className="material-icons">email</span>
            </button>
            <button className="p-1.5 text-gray-500 hover:bg-gray-100 rounded-full">
              <span className="material-icons">settings</span>
            </button>
          </div>
          <div className="relative flex items-center gap-1 bg-white rounded-xl shadow-soft px-2">
            <input
              placeholder="Search users..."
              value={topSearchQuery}
              onChange={e => setTopSearchQuery(e.target.value)}
              onFocus={() => topSearchQuery && setShowTopSearch(true)}
              onBlur={() => setTimeout(() => setShowTopSearch(false), 200)}
              className="border-0 bg-transparent px-2 py-1.5 text-sm w-48 focus:ring-0 outline-none"
            />
            <div className="h-5 w-px bg-gray-200"></div>
            <button className="p-1.5 text-gray-500 hover:bg-gray-100 rounded-full">
              <span className="material-icons text-lg">search</span>
            </button>
            {showTopSearch && topSearchResults.length > 0 && (
              <div className="absolute top-full right-0 mt-2 w-72 bg-white rounded-xl shadow-xl border border-gray-100 z-50 overflow-hidden">
                {topSearchResults.map(u => (
                  <button
                    key={u._id}
                    onClick={() => {
                      // Start direct chat logic
                      (async () => {
                        const r = await fetch(`${API}/api/conversations/direct`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ userId: u._id }) })
                        const conv = await r.json()
                        setConversations(cs => (cs.find(c => c._id === conv._id) ? cs : [conv, ...cs]))
                        setActiveId(conv._id)
                        setTopSearchQuery('')
                        setShowTopSearch(false)
                      })()
                    }}
                    className="w-full text-left px-4 py-3 hover:bg-sky-50 flex items-center gap-3 transition-colors border-b border-gray-50 last:border-0"
                  >
                    <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 grid place-items-center font-semibold text-xs">
                      {u.username?.charAt(0).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm text-gray-900 truncate">{u.username}</div>
                      <div className="text-xs text-gray-500 truncate">{u.email}</div>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
          <button onClick={() => setProfileOpen(true)} className="ml-2 w-8 h-8 rounded-full border grid place-items-center bg-indigo-100 text-indigo-700 font-semibold">
            {String(user.username || '?').charAt(0).toUpperCase()}
          </button>
        </div>
      </div>

      <div className="h-[calc(100%-3.5rem)] bg-white rounded-3xl shadow-soft flex overflow-hidden">
        <div className="w-72 flex-none border-r h-full">
          <LeftPanel user={user} conversations={conversations} activeId={activeId} onPick={setActiveId} onNew={() => setOpenNew(true)} />
        </div>
        <div className="flex-1 min-w-0 h-full">
          <CenterPanel
               user={user}
               socket={socket}
               typingUsers={typingUsers}
               setShowMembers={setShowMembers}
               setInfoMsg={setInfoMsg}
               refreshMessages={refreshMessages}
               onStartCall={startCall}
               selectedMessages={selectedMessages}
               setSelectedMessages={setSelectedMessages}
               getDeletedIdsForConv={getDeletedIdsForConv}
               addDeletedForMe={addDeletedForMe}
             />
        </div>
        <div className="w-72 flex-none border-l h-full hidden xl:block">
          <RightPanel user={user} onOpenProfile={() => setProfileOpen(true)} />
        </div>
      </div>
      {openNew && <NewChatModal onClose={() => setOpenNew(false)} />}
      {profileOpen && <ProfileModal user={user} onClose={() => setProfileOpen(false)} onLogout={onLogout} />}
      {showMembers && <MembersModal conv={conversations.find(c => c._id === activeId)} onClose={() => setShowMembers(false)} />}
      {infoMsg && <MessageInfoModal message={infoMsg} conv={conversations.find(c => c._id === activeId)} onClose={() => setInfoMsg(null)} />}
      {incomingCall && !currentCall && (
        <IncomingCallModal
          call={incomingCall}
          conversations={conversations}
          onAccept={acceptIncomingCall}
          onReject={rejectIncomingCall}
        />
      )}
      {toast && <Toast notification={toast} onClose={() => setToast(null)} />}

      {/* Force Change Password Modal */}
      {user && user.mustChangePassword && (
        <ChangePasswordModal
          token={token}
          onComplete={(updatedUser) => {
            setUser(updatedUser)
            // Update localStorage as well
            localStorage.setItem('user', JSON.stringify(updatedUser))
          }}
        />
      )}
    </div>
  )
}

function Toast({ notification, onClose }) {
  useEffect(() => {
    const t = setTimeout(onClose, 3000)
    return () => clearTimeout(t)
  }, [notification])

  if (!notification) return null

  return (
    <div className="fixed top-4 right-4 z-50 bg-white rounded-xl shadow-xl p-4 border border-gray-100 animate-bounce max-w-sm cursor-pointer flex items-start gap-3" onClick={onClose}>
      <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 grid place-items-center text-xs font-semibold flex-shrink-0">
        {(notification.title || 'N').charAt(0).toUpperCase()}
      </div>
      <div>
        <div className="font-semibold text-sm">{notification.title}</div>
        <div className="text-xs text-gray-500 line-clamp-2">{notification.message}</div>
      </div>
    </div>
  )
}

function LeftPanel({ user, conversations, activeId, onPick, onNew }) {
  const { leftTab, setLeftTab, unreadCounts, token, setConversations, setActiveId } = useStore()
  const tab = leftTab
  const [q, setQ] = useState('')
  const [allUsers, setAllUsers] = useState([])
  const [searchMode, setSearchMode] = useState(false)

  // Fetch all users for search
  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(`${API}/api/users`)
        const list = await r.json()
        setAllUsers(list.filter(u => String(u._id) !== String(user._id)))
      } catch (e) {
        console.error('Failed to load users', e)
      }
    })()
  }, [user._id])

  // Ensure unique conversations (avoid duplicate keys) and sort by recency
  const uniqueConversations = [...new Map(conversations.map(c => [c._id, c])).values()]
  const sorted = uniqueConversations.sort((a, b) => {
    const ta = new Date(a.lastMessageAt || a.updatedAt || a.createdAt || 0).getTime()
    const tb = new Date(b.lastMessageAt || b.updatedAt || b.createdAt || 0).getTime()
    return tb - ta
  })

  const list = sorted.filter(c => {
    if (tab === 'direct' && c.type !== 'direct') return false
    if (tab === 'group' && c.type !== 'group') return false
    if (!q) return true
    const other = c.members?.find(m => String(m._id) !== String(user._id))
    const name = c.type === 'group' ? (c.name || '') : (other?.username || '')
    return name.toLowerCase().includes(q.toLowerCase())
  })

  // Search results from all users (only for Direct tab)
  const searchResults = (tab === 'direct' && q) ? allUsers.filter(u =>
    u.username?.toLowerCase().includes(q.toLowerCase()) ||
    u.email?.toLowerCase().includes(q.toLowerCase())
  ) : []

  const startDirect = async (userId) => {
    try {
      const r = await fetch(`${API}/api/conversations/direct`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ userId })
      })
      const conv = await r.json()
      setConversations(cs => (cs.find(c => c._id === conv._id) ? cs : [conv, ...cs]))
      setActiveId(conv._id)
      setQ('')
      setSearchMode(false)
    } catch (e) {
      console.error('Failed to start conversation', e)
    }
  }

  // Calculate unread counts for each tab
  const directUnread = conversations
    .filter(c => c.type === 'direct')
    .reduce((sum, c) => sum + ((unreadCounts || {})[c._id] || 0), 0)

  const groupUnread = conversations
    .filter(c => c.type === 'group' && (c.name || '').toLowerCase() !== 'lobby')
    .reduce((sum, c) => sum + ((unreadCounts || {})[c._id] || 0), 0)

  return (
    <div className="h-full bg-sky-50/40 p-4">
      <div className="flex items-center justify-between mb-4">
        <div className="font-semibold">Chats</div>
      </div>
      <div className="grid grid-cols-2 text-xs bg-white rounded-xl shadow-soft overflow-hidden mb-3">
        {['Direct', 'Group'].map((t) => {
          const key = t.toLowerCase()
          const active = tab === key
          const hasUnread = key === 'direct' ? directUnread > 0 : groupUnread > 0
          return (
            <button key={t} onClick={() => { setLeftTab(key); setQ(''); setSearchMode(false) }} className={`py-2 relative ${active ? 'bg-primary text-white' : 'text-gray-600'}`}>
              {t}
              {hasUnread && (
                <span className="absolute top-1 right-2 w-2 h-2 bg-red-500 rounded-full"></span>
              )}
            </button>
          )
        })}
      </div>
      <div className="mb-2">
        <input
          value={q}
          onChange={(e) => {
            setQ(e.target.value)
            setSearchMode(e.target.value.length > 0)
          }}
          className="w-full rounded-xl border-0 bg-white shadow-soft px-3 py-2 text-sm"
          placeholder={tab === 'direct' ? 'Search conversations or users...' : 'Search groups...'}
        />
      </div>

      {/* Create New Group button (only in Group tab) */}
      {tab === 'group' && (
        <button
          onClick={onNew}
          className="w-full mb-3 bg-primary text-white rounded-xl px-3 py-2 text-sm font-medium hover:bg-primary/90 transition-colors flex items-center justify-center gap-2"
        >
          <span>+</span>
          <span>Create New Group</span>
        </button>
      )}

      <div className="space-y-2 overflow-y-auto h-[calc(100%-180px)] pr-2">
        {tab === 'direct' && searchMode && searchResults.length > 0 ? (
          // Show user search results in Direct tab
          searchResults.map(u => (
            <button key={u._id} onClick={() => startDirect(u._id)} className="w-full text-left bg-white rounded-xl px-3 py-2 shadow-soft hover:shadow">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-gray-200 text-gray-700 grid place-items-center font-semibold">
                  {u.username?.charAt(0).toUpperCase()}
                </div>
                <div className="flex-1">
                  <div className="font-medium text-sm">{u.username}</div>
                  <div className="text-xs text-gray-500">{u.email}</div>
                </div>
              </div>
            </button>
          ))
        ) : tab === 'direct' && searchMode && searchResults.length === 0 && list.length === 0 ? (
          <div className="text-center text-gray-500 text-sm py-4">No users or conversations found</div>
        ) : (
          // Show conversations (filtered by search)
          list.map(c => {
            const other = c.type === 'group' ? null : c.members.find(m => m._id !== user._id)
            const isOnline = other && dayjs().diff(dayjs(other.lastSeenAt), 'minute') < 5
            const unread = (unreadCounts || {})[c._id] || 0

            return (
              <button
                key={c._id}
                onClick={() => onPick(c._id)}
                className={`w-full text-left rounded-xl px-3 py-3 transition-all ${activeId === c._id
                  ? 'bg-primary/10 shadow-md ring-2 ring-primary/30'
                  : unread > 0
                    ? 'bg-white shadow-soft-dark hover:shadow-md'
                    : 'bg-white shadow-soft hover:shadow'
                  }`}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-full grid place-items-center font-semibold text-sm ${unread > 0
                    ? 'bg-primary text-white'
                    : 'bg-indigo-100 text-indigo-700'
                    }`}>
                    {c.type === 'group' ? (c.name?.charAt(0) || 'G') : (other?.username?.charAt(0) || 'D')}
                  </div>
                  <div className="flex-1 flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <div className={`text-sm truncate ${unread > 0 ? 'font-bold text-gray-900' : 'font-medium text-gray-700'}`}>
                        {c.type === 'group' ? c.name : (other?.username || 'Direct')}
                      </div>
                      {c.type !== 'group' && isOnline && (
                        <div className="text-[10px] text-green-600 flex items-center gap-1 mt-0.5">
                          <span className="w-1.5 h-1.5 bg-green-600 rounded-full"></span>
                          <span>Online</span>
                        </div>
                      )}
                    </div>
                    {unread > 0 && (
                      <div className="ml-2 min-w-[20px] h-5 px-2 flex items-center justify-center rounded-full bg-primary text-white text-xs font-bold shadow-sm">
                        {unread > 99 ? '99+' : unread}
                      </div>
                    )}
                  </div>
                </div>
              </button>
            )
          })
        )}
      </div>
    </div>
  )
}

function CenterPanel({ user, socket, typingUsers, setShowMembers, setInfoMsg, refreshMessages, onStartCall, selectedMessages, setSelectedMessages, getDeletedIdsForConv, addDeletedForMe }) {
  const { activeId, messages, pushMessage, token, conversations, setConversations, setActiveId, setMessages, removeMessage } = useStore()
  const [text, setText] = useState('')
  const [editingMessageId, setEditingMessageId] = useState(null)
  const [editingMessageContent, setEditingMessageContent] = useState('')
  const [showEmoji, setShowEmoji] = useState(false)
  const [showCallMenu, setShowCallMenu] = useState(false)
  const [showNotifications, setShowNotifications] = useState(false)
  const [showOptionsMenu, setShowOptionsMenu] = useState(false)
  const [previewFile, setPreviewFile] = useState(null)
  const [isUploading, setIsUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploadSession, setUploadSession] = useState(null)
  const listRef = useRef(null)
  const fileInputRef = useRef(null)
  const selectionHeaderRef = useRef(null)
  const hiddenIds = activeId ? getDeletedIdsForConv(activeId) : new Set()
  const convMessages = activeId ? ((messages[activeId] || []).filter(m => !hiddenIds.has(String(m._id)))) : []

  const conv = useStore.getState().conversations.find(c => c._id === activeId)
  const membersCount = conv?.members?.length || 1
  const other = conv?.members?.find(m => String(m._id) !== String(user._id))

  const handleSaveEdit = async () => {
    if (!editingMessageId || !editingMessageContent.trim()) return

    try {
      const res = await fetch(`${API}/api/messages/${editingMessageId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ content: editingMessageContent })
      })
      if (res.ok) {
        useStore.getState().updateMessage(activeId, editingMessageId, { content: editingMessageContent, editedAt: new Date().toISOString() })
        setEditingMessageId(null)
        setEditingMessageContent('')
      } else {
        alert('Failed to edit message')
      }
    } catch (e) {
      console.error('Error editing message:', e)
      alert('Failed to edit message')
    }
  }

  const handleCancelEdit = () => {
    setEditingMessageId(null)
    setEditingMessageContent('')
  }

  // Close menus when switching chats
  useEffect(() => {
    setShowOptionsMenu(false)
    setShowCallMenu(false)
    setShowEmoji(false)
    setSelectedMessages(new Set())
  }, [activeId])

  useEffect(() => {
    if (selectedMessages.size === 0) return
    const onDocClick = (e) => {
      if (!selectionHeaderRef.current) return
      const clickedInsideHeader = selectionHeaderRef.current.contains(e.target)
      const clickedOnBubble = !!(e.target && e.target.closest && e.target.closest('[data-role="message-bubble"]'))
      if (!clickedInsideHeader && !clickedOnBubble) {
        setSelectedMessages(new Set())
        setShowOptionsMenu(false)
      }
    }
    document.addEventListener('mousedown', onDocClick)
    return () => document.removeEventListener('mousedown', onDocClick)
  }, [selectedMessages.size])

  useEffect(() => {
    listRef.current?.lastElementChild?.scrollIntoView({ behavior: 'smooth' })
  }, [convMessages.length])

  const handleSend = async () => {
    // Allow sending if there's text OR a file
    if ((!text.trim() && !previewFile) || !activeId) return

    // If there's a file, it should already be uploaded (via handleFileSelect)
    // Now send message metadata via REST API
    if (previewFile && previewFile.fileId) {
      try {
        const res = await fetch(`${API}/api/messages/send`, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}` 
          },
          body: JSON.stringify({
            conversationId: activeId,
            messageText: text.trim() || '',
            fileId: previewFile.fileId,
            fileURL: previewFile.fileURL,
            fileName: previewFile.name,
            fileType: previewFile.type,
            fileSize: previewFile.size
          })
        })
        
        if (!res.ok) {
          const error = await res.json()
          throw new Error(error.error || 'Failed to send message')
        }
        
        const message = await res.json()
        
        // Add to local state (server broadcasts via Socket.IO, but add locally for instant UI)
        pushMessage(activeId, {
          ...message,
          tempId: message.tempId || Math.random().toString(36).slice(2)
        })
        
        setText('')
        setPreviewFile(null)
        setUploadSession(null)
        setUploadProgress(0)
        
        if (socket) {
          socket.emit('stop_typing', { conversationId: activeId })
        }
      } catch (e) {
        console.error('Error sending message:', e)
        alert(e.message || 'Failed to send message. Please try again.')
      }
    } else if (!previewFile) {
      // Text-only message - can use WebSocket or REST API
      const tempId = Math.random().toString(36).slice(2)
      const msg = {
        _id: tempId,
        tempId,
        conversation: activeId,
        sender: user,
        content: text.trim(),
        createdAt: new Date().toISOString(),
        deliveredTo: [],
        seenBy: []
      }
      pushMessage(activeId, msg)

      // Send via WebSocket (text-only)
      if (socket) {
        socket.emit('message_send', {
          conversationId: activeId,
          content: text.trim(),
          tempId
        })
        socket.emit('stop_typing', { conversationId: activeId })
      }

      setText('')
    } else {
      // File selected but not uploaded yet
      alert('Please wait for file upload to complete')
    }
  }

  const isTyping = (typingUsers[activeId] && [...typingUsers[activeId]].filter(id => id !== user._id).length > 0)

  const onInput = (v) => {
    setText(v)
    if (socket && activeId) {
      if (v) socket.emit('typing', { conversationId: activeId })
      else socket.emit('stop_typing', { conversationId: activeId })
    }
  }

  const handleEmojiClick = (emojiData) => {
    setText(prev => prev + emojiData.emoji)
    setShowEmoji(false)
  }

  const handleFileSelect = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    
    // Check file size (25MB limit)
    if (file.size > 25 * 1024 * 1024) {
      alert('File size should be less than 25MB')
      return
    }
    
    // Create preview URL
    const fileUrl = URL.createObjectURL(file)
    setPreviewFile({
      file,
      url: fileUrl,
      name: file.name,
      type: file.type,
      size: file.size
    })
    
    // Step 1: Create upload session (WhatsApp-like flow)
    setIsUploading(true)
    setUploadProgress(0)
    
    try {
      const sessionRes = await fetch(`${API}/api/media/create-upload-session`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}` 
        },
        body: JSON.stringify({
          fileName: file.name,
          fileType: file.type,
          fileSize: file.size
        })
      })
      
      if (!sessionRes.ok) {
        const error = await sessionRes.json()
        throw new Error(error.error || 'Failed to create upload session')
      }
      
      const sessionData = await sessionRes.json()
      setUploadSession(sessionData)
      
      // Step 2: Upload file directly to uploadURL
      const formData = new FormData()
      formData.append('file', file)
      
      const xhr = new XMLHttpRequest()
      
      // Track upload progress
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const percentComplete = (e.loaded / e.total) * 100
          setUploadProgress(percentComplete)
        }
      })
      
      xhr.onload = () => {
        if (xhr.status === 200) {
          const uploadResult = JSON.parse(xhr.responseText)
          setPreviewFile(prev => ({
            ...prev,
            fileId: uploadResult.fileId,
            fileURL: uploadResult.fileURL
          }))
          setUploadProgress(100)
          setIsUploading(false)
        } else {
          throw new Error('Upload failed')
        }
      }
      
      xhr.onerror = () => {
        alert('Upload failed. Please try again.')
        setIsUploading(false)
        setUploadProgress(0)
        setPreviewFile(null)
        setUploadSession(null)
      }
      
      xhr.open('POST', sessionData.uploadURL)
      xhr.setRequestHeader('Authorization', `Bearer ${token}`)
      xhr.send(formData)
      
    } catch (e) {
      console.error('File upload error:', e)
      alert(e.message || 'Failed to upload file. Please try again.')
      setIsUploading(false)
      setUploadProgress(0)
      setPreviewFile(null)
      setUploadSession(null)
    }
    
    // Reset input
    if (fileInputRef.current) fileInputRef.current.value = ''
  }
  
  // Clean up object URL when previewFile changes or component unmounts
  useEffect(() => {
    const currentUrl = previewFile?.url
    return () => {
      if (currentUrl) {
        URL.revokeObjectURL(currentUrl)
      }
    }
  }, [previewFile?.url])

  const toggleSelect = (id) => {
    setSelectedMessages(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const myId = String(user._id)
  const selectedMsgObjs = convMessages.filter(m => selectedMessages.has(m._id))
  const allMine = selectedMsgObjs.length > 0 && selectedMsgObjs.every(m => String(m.sender?._id || m.sender) === myId)
  const allUnseenByOthers = allMine

  if (!activeId) {
    return <div className="h-full flex flex-col">
      <div className="px-5 py-3 border-b flex items-center justify-between">
        <div className="font-semibold">Conversation</div>
        <div className="flex items-center gap-2 text-gray-400"></div>
      </div>
      <div className="flex-1 grid place-items-center bg-sky-50/40 text-gray-400 select-none">
        <div className="text-sm">Start your conversation</div>
      </div>
    </div>
  }

  return (
    <div className="h-full flex flex-col">
      <div ref={selectionHeaderRef} className="px-5 py-3 border-b flex items-center justify-between relative h-16">
        {selectedMessages.size > 0 ? (
          <>
            <div className="flex items-center gap-3">
              <button onClick={() => setSelectedMessages(new Set())} className="p-2 hover:bg-gray-100 rounded-full" title="Clear Selection">
                <span className="material-icons">close</span>
              </button>
              <div className="font-semibold text-sm">{selectedMessages.size} selected</div>
            </div>
            <div className="flex items-center gap-3">
              <div className="relative">
                <button
                  onClick={() => setShowOptionsMenu(v => !v)}
                  className="p-2 hover:bg-gray-100 rounded-lg"
                  title="Options"
                >
                  <span className="material-icons">more_vert</span>
                </button>
                {showOptionsMenu && (
                  <div className="absolute right-0 mt-1 w-52 bg-white rounded-xl shadow-lg border text-sm z-10">
                    {selectedMessages.size === 1 && conv?.type === 'group' && (
                      <button
                        onClick={() => {
                          const msgId = [...selectedMessages][0];
                          const msg = convMessages.find(m => m._id === msgId);
                          if (msg) setInfoMsg(msg);
                          setSelectedMessages(new Set());
                          setShowOptionsMenu(false);
                        }}
                        className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-50 text-left rounded-t-xl"
                      >
                        <span className="material-icons">info</span>
                        <span>Info</span>
                      </button>
                    )}
                    {selectedMessages.size === 1 && (() => {
                      const msg = convMessages.find(m => m._id === [...selectedMessages][0])
                      const mine = msg && String(msg.sender?._id || msg.sender) === String(user._id)
                      return mine
                    })() && (
                      <button
            onClick={() => {
              const msgId = [...selectedMessages][0]
              const msg = convMessages.find(m => m._id === msgId)
              setEditingMessageId(msgId)
              setEditingMessageContent(msg?.content || '')
              setSelectedMessages(new Set())
              setShowOptionsMenu(false)
            }}
            className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-50 text-left"
          >
            <span className="material-icons">edit</span>
            <span>Edit</span>
          </button>
                    )}
                    <button
                      onClick={async () => {
                        if (!confirm(`Delete ${selectedMessages.size} message(s) for yourself?`)) return
                        try {
                          // Optimistic update
                          const convId = activeId;
                          [...selectedMessages].forEach(msgId => {
                            removeMessage(convId, msgId)
                          })
                          addDeletedForMe(convId, [...selectedMessages])

                          setSelectedMessages(new Set())
                          setShowOptionsMenu(false)
                        } catch (e) {
                          console.error(e)
                          alert('Failed to delete')
                        }
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-50 text-left"
                    >
                      <span className="material-icons">delete</span>
                      <span>Delete for Me</span>
                    </button>

                    {allMine && allUnseenByOthers && (
                      <button
                        onClick={async () => {
                          if (!confirm(`Delete ${selectedMessages.size} message(s) for everyone?`)) return
                          try {
                            const promises = [...selectedMessages].map(msgId =>
                              fetch(`${API}/api/messages/${msgId}?everyone=true`, {
                                method: 'DELETE',
                                headers: { Authorization: `Bearer ${token}` }
                              })
                            )
                            await Promise.all(promises)

                            setSelectedMessages(new Set())
                            setShowOptionsMenu(false)
                          } catch (e) {
                            console.error(e)
                            alert('Failed to delete')
                          }
                        }}
                        className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-50 text-left rounded-b-xl"
                      >
                        <span className="material-icons">delete</span>
                        <span>Delete for Everyone</span>
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          </>
        ) : (
          <>
            <div>
              <div className="font-bold text-lg text-gray-900">{conv?.type === 'group' ? (conv?.name || 'Group') : (other?.username || 'Conversation')}</div>
              {conv?.type === 'group' && conv?.members && (
                <div className="text-xs text-gray-500">
                  {conv.members.length} members
                </div>
              )}
              {other && (
                <div className="text-xs flex items-center gap-1">
                  {/* Show online if last seen within 5 minutes */}
                  {other.lastSeenAt && dayjs().diff(dayjs(other.lastSeenAt), 'minute') < 5 ? (
                    <>
                      <span className="w-2 h-2 bg-green-600 rounded-full"></span>
                      <span className="text-green-600 font-medium">Online</span>
                    </>
                  ) : (
                    <span className="text-gray-500">
                      {other.lastSeenAt
                        ? `Last seen ${dayjs(other.lastSeenAt).fromNow()}`
                        : 'Offline'}
                    </span>
                  )}
                </div>
              )}
            </div>
              <div className="flex items-center gap-2 text-gray-400">
                {conv && (
                  <>
                    <div className="relative">
                    <button
                      title="Calls"
                      className="w-9 h-9 rounded-full hover:bg-gray-100 flex items-center justify-center text-base"
                      onClick={() => setShowCallMenu(v => !v)}
                    >
                      <span className="material-icons">call</span>
                    </button>
                    {showCallMenu && (
                      <div className="absolute right-0 mt-1 w-44 bg-white rounded-xl shadow-lg border text-sm z-10">
                        <button
                          className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-50 text-left"
                          onClick={() => { setShowCallMenu(false); onStartCall('video') }}
                        >
                          <span className="material-icons">videocam</span>
                          <span>Video call</span>
                        </button>
                        <button
                          className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-50 text-left"
                          onClick={() => { setShowCallMenu(false); onStartCall('audio') }}
                        >
                          <span className="material-icons">call</span>
                          <span>Audio call</span>
                        </button>
                      </div>
                    )}
                  </div>
                  </>
                )}
                <button
                  title="Refresh messages"
                  className="p-2 rounded-lg hover:bg-gray-100"
                  onClick={refreshMessages}
                >
                <span className="material-icons">refresh</span>
              </button>
              <div className="relative">
                <button
                  title="Options"
                  className="w-9 h-9 rounded-full hover:bg-gray-100 flex items-center justify-center text-base"
                  onClick={() => setShowOptionsMenu(v => !v)}
                >
                  <span className="material-icons">more_vert</span>
                </button>
                {showOptionsMenu && (
                  <div className="absolute right-0 mt-1 w-52 bg-white rounded-xl shadow-lg border text-sm z-10">
                    {conv?.type === 'direct' ? (
                      // Direct conversation: Delete for current user only
                      <button
                        className="w-full flex items-center gap-2 px-3 py-2 hover:bg-red-50 text-red-600 text-left rounded-xl"
                        onClick={async () => {
                          if (!confirm('Delete this conversation? This will only remove it from your chat list.')) return
                          try {
                            await fetch(`${API}/api/conversations/${activeId}/leave`, {
                              method: 'POST',
                              headers: { Authorization: `Bearer ${token}` }
                            })
                            setConversations(cs => cs.filter(c => c._id !== activeId))
                            setActiveId(null)
                            setShowOptionsMenu(false)
                          } catch (e) {
                            console.error(e)
                            alert('Failed to delete conversation')
                          }
                        }}
                      >
                        <span className="material-icons">delete</span>
                        <span>Delete Conversation</span>
                      </button>
                    ) : (
                      // Group conversation: Members + Clear + Leave
                      <>
                        <button
                          className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-50 text-left rounded-t-xl"
                          onClick={() => {
                            setShowMembers(true)
                            setShowOptionsMenu(false)
                          }}
                        >
                          <span className="material-icons">group</span>
                          <span>Group Members</span>
                        </button>
                        <button
                          className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-50 text-left"
                          onClick={async () => {
                            if (!confirm('Clear all messages in this group? This will only clear messages from your view.')) return
                            try {
                              await fetch(`${API}/api/conversations/${activeId}/clear`, {
                                method: 'POST',
                                headers: { Authorization: `Bearer ${token}` }
                              })
                              // Clear messages locally
                              setMessages(activeId, [])
                              setShowOptionsMenu(false)
                            } catch (e) {
                              console.error(e)
                              alert('Failed to clear messages')
                            }
                          }}
                        >
                          <span className="material-icons">cleaning_services</span>
                          <span>Clear Conversation</span>
                        </button>
                        <button
                          className="w-full flex items-center gap-2 px-3 py-2 hover:bg-red-50 text-red-600 text-left rounded-b-xl"
                          onClick={async () => {
                            if (!confirm('Leave this group? The group will be removed from your chat list.')) return
                            try {
                              await fetch(`${API}/api/conversations/${activeId}/leave`, {
                                method: 'POST',
                                headers: { Authorization: `Bearer ${token}` }
                              })
                              setConversations(cs => cs.filter(c => c._id !== activeId))
                              setActiveId(null)
                              setShowOptionsMenu(false)
                            } catch (e) {
                              console.error(e)
                              alert('Failed to leave group')
                            }
                          }}
                        >
                          <span className="material-icons">logout</span>
                          <span>Leave Group</span>
                        </button>
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>
      <div
        ref={listRef}
        className="flex-1 overflow-y-auto p-6 space-y-3 relative bg-gradient-to-br from-surface via-white to-surface-dark"
        onScroll={(e) => {
          // Find the current visible date while scrolling
          const scrollTop = e.target.scrollTop
          const messages = convMessages.filter(m => m.content || (m.attachments && m.attachments.length > 0))

          // Simple logic: show the date of the first message in view
          if (messages.length > 0) {
            const firstVisibleDate = dayjs(messages[0].createdAt).format('DD-MM-YYYY')
            // You can add state here to show sticky date if needed
          }
        }}
      >
        {convMessages.length === 0 && null}
        {convMessages
          .filter(m => m.content || (m.attachments && m.attachments.length > 0))
          .map((m, index, arr) => {
            // Check if we need to show a date stamp
            const currentDate = dayjs(m.createdAt).format('DD-MM-YYYY')
            const prevDate = index > 0 ? dayjs(arr[index - 1].createdAt).format('DD-MM-YYYY') : null
            const showDateStamp = index === 0 || currentDate !== prevDate

            return (
              <React.Fragment key={m._id}>
                {showDateStamp && (
                  <div className="flex justify-center my-4 sticky top-2 z-10">
                    <div className="bg-white/90 backdrop-blur-md px-4 py-1.5 rounded-full shadow-md text-xs font-medium text-gray-700 border border-gray-200">
                      {currentDate}
                    </div>
                  </div>
                )}
                <MessageBubble
                  me={user._id}
                  m={m}
                  totalMembers={membersCount}
                  conv={conv}
                  onInfo={() => setInfoMsg(m)}
                  selected={selectedMessages.has(m._id)}
                  onSelect={() => toggleSelect(m._id)}
                  editingMessageId={editingMessageId}
                  editingMessageContent={editingMessageContent}
                  setEditingMessageContent={setEditingMessageContent}
                  handleSaveEdit={handleSaveEdit}
                  handleCancelEdit={handleCancelEdit}
                />
              </React.Fragment>
            )
          })}
        {isTyping && <div className="text-xs text-gray-500">Typing...</div>}
      </div>
      <div className="p-4 border-t bg-white">
        {/* File Preview with Upload Progress */}
        {previewFile && (
          <div className="mb-3 p-3 bg-gray-50 rounded-lg">
            <div className="flex items-center gap-3">
              {previewFile.type.startsWith('image/') ? (
                <img src={previewFile.url} alt={previewFile.name} className="w-16 h-16 object-cover rounded" />
              ) : (
                <div className="w-16 h-16 bg-gray-200 rounded flex items-center justify-center">
                  <span className="text-2xl">📎</span>
                </div>
              )}
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-gray-900 truncate">{previewFile.name}</div>
                <div className="text-xs text-gray-500">{(previewFile.size / 1024).toFixed(1)} KB</div>
                {isUploading && (
                  <div className="mt-2">
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-primary h-2 rounded-full transition-all duration-300" 
                        style={{ width: `${uploadProgress}%` }}
                      ></div>
                    </div>
                    <div className="text-xs text-gray-600 mt-1">Uploading {Math.round(uploadProgress)}%</div>
                  </div>
                )}
                {!isUploading && previewFile.fileId && (
                  <div className="text-xs text-green-600 mt-1">✓ Uploaded</div>
                )}
              </div>
              <button 
                onClick={() => {
                  URL.revokeObjectURL(previewFile.url)
                  setPreviewFile(null)
                  setUploadSession(null)
                  setUploadProgress(0)
                  setIsUploading(false)
                }}
                className="px-3 py-1 text-sm text-gray-600 hover:text-gray-900"
                disabled={isUploading}
              >
                ✕
              </button>
            </div>
          </div>
        )}
        <div className="flex items-center gap-2">
          <div className="relative">
            <button onClick={() => setShowEmoji(!showEmoji)} className="px-3 py-2 rounded-lg bg-gray-100" title="Emoji">
              <span className="material-icons">emoji_emotions</span>
            </button>
            {showEmoji && (
              <div className="absolute bottom-12 left-0 z-10">
                <EmojiPicker onEmojiClick={handleEmojiClick} />
              </div>
            )}
          </div>
          <button onClick={() => fileInputRef.current?.click()} className="px-3 py-2 rounded-lg bg-gray-100" title="Attach">
            <span className="material-icons">attach_file</span>
          </button>
          <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileSelect} />
          <input 
            value={text} 
            onChange={(e) => onInput(e.target.value)} 
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend() } }} 
            className="flex-1 rounded-full border-0 bg-sky-50 px-4 py-3" 
            placeholder={previewFile ? "Add a message (optional)..." : "Say something..."} 
            disabled={isUploading}
          />
          <button 
            onClick={handleSend} 
            disabled={isUploading || (!text.trim() && (!previewFile || !previewFile.fileId))}
            className="bg-primary text-white px-4 py-3 rounded-full disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isUploading ? `Uploading ${Math.round(uploadProgress)}%` : 'Send'}
          </button>
        </div>
        {showNotifications && (
          <div className="absolute right-4 top-16 w-80 bg-white shadow-lg border rounded-xl z-20">
            <div className="px-3 py-2 flex items-center justify-between border-b">
              <div className="font-semibold text-sm">Notifications</div>
              <button className="text-xs text-gray-600" onClick={() => setShowNotifications(false)}>Close</button>
            </div>
            <div className="max-h-80 overflow-y-auto p-2 space-y-2">
              {(useStore.getState().notifications || []).length === 0 ? (
                <div className="text-xs text-gray-500 px-2 py-3">No notifications</div>
              ) : (
                useStore.getState().notifications.map(n => (
                  <button key={n.id} onClick={() => { setShowNotifications(false); setActiveId(n.conversationId) }} className="w-full text-left px-2 py-2 hover:bg-gray-50 rounded-lg">
                    <div className="text-sm font-medium">{n.title}</div>
                    <div className="text-xs text-gray-600 truncate">{n.message}</div>
                  </button>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function MessageBubble({ m, me, totalMembers, conv, onInfo, selected, onSelect, editingMessageId, editingMessageContent, setEditingMessageContent, handleSaveEdit, handleCancelEdit }) {
  console.log('MessageBubble props:', { handleSaveEdit, handleCancelEdit });
  const mine = String(m.sender?._id || m.sender) === String(me)
  const senderName = m.sender?.username || (conv?.members || []).find(x => String(x._id) === String(m.sender))?.username || (mine ? 'You' : 'User')

  return (
    <div className={`flex ${mine ? 'justify-end' : 'justify-start'}`}>
      <div
        onClick={onSelect}
        data-role="message-bubble"
        className={`max-w-[70%] rounded-2xl px-4 py-3 shadow cursor-pointer transition-colors ${selected ? 'ring-2 ring-offset-1 ring-primary' : ''} ${mine ? 'bg-primary text-white rounded-br-sm' : 'bg-white rounded-bl-sm'}`}
      >
        {conv?.type === 'group' && (
          <div className={`text-[11px] mb-1 ${mine ? 'text-white/90' : 'text-gray-700'}`}>{senderName}</div>
        )}
        {m.attachments && m.attachments.length > 0 && (
          <div className="mb-2 space-y-2">
            {m.attachments.map((att, i) => (
              <div key={i}>
                {att.type.startsWith('image/') ? (
                  <img src={att.url} alt={att.name} className="max-w-full rounded-lg" />
                ) : (
                  <a href={att.url} target="_blank" rel="noopener noreferrer" className={`flex items-center gap-2 p-2 rounded text-xs ${mine ? 'bg-white/20 text-white' : 'bg-gray-100 text-gray-700'}`}>
                    <span>📎</span>
                    <span>{att.name}</span>
                  </a>
                )}
              </div>
            ))}
          </div>
        )}
        <div className="text-sm whitespace-pre-wrap">
          {editingMessageId === m._id ? (
            <>
              <input
                type="text"
                value={editingMessageContent}
                onChange={(e) => setEditingMessageContent(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleSaveEdit()
                  if (e.key === 'Escape') handleCancelEdit()
                }}
                className="w-full p-1 rounded bg-gray-100 text-gray-800"
              />
              <div className="flex gap-2 mt-2">
                <button onClick={handleSaveEdit} className="px-3 py-1 bg-primary text-white rounded-full text-xs">Save</button>
                <button onClick={handleCancelEdit} className="px-3 py-1 bg-gray-300 text-gray-800 rounded-full text-xs">Cancel</button>
              </div>
            </>
          ) : (
            m.content
          )}
        </div>
        <div className={`text-[10px] mt-1 flex items-center gap-2 ${mine ? 'text-white/80' : 'text-gray-500'}`}>
          <span>{dayjs(m.createdAt).format('HH:mm')}</span>
          {m.editedAt && <span className="opacity-70">(edited)</span>}
          {mine && <StatusIcon m={m} me={me} totalMembers={totalMembers} />}
        </div>
      </div>
    </div>
  )
}

function StatusIcon({ m, me, totalMembers }) {
  // Logic:
  // 1. If seenBy includes everyone (or at least one other person in direct), show Seen
  // 2. If deliveredTo includes everyone (or at least one other person in direct), show Delivered
  // 3. Else Sent

  // Exclude self from counts
  const seenCount = (m.seenBy || []).filter(id => String(id) !== String(me)).length
  const deliveredCount = (m.deliveredTo || []).filter(id => String(id) !== String(me)).length

  // For direct chat, we just need 1 other person
  // For group, we ideally want everyone, but for now let's say if ANYONE saw it, it's seen

  if (seenCount > 0) {
    return (
      <span className="flex items-center gap-1" title={`Seen by ${seenCount}`}>
        <span className="text-xs">✔✔</span>
        <span>Seen</span>
      </span>
    )
  }

  if (deliveredCount > 0) {
    return (
      <span className="flex items-center gap-1" title={`Delivered to ${deliveredCount}`}>
        <span className="text-[10px]">●</span>
        <span>Delivered</span>
      </span>
    )
  }

  return (
    <span className="flex items-center gap-1" title="Sent">
      <span className="text-[10px]">○</span>
      <span>Sent</span>
    </span>
  )
}

function CreateUserModal({ onClose, token }) {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess(null)
    setLoading(true)

    try {
      const res = await fetch(`${API}/api/admin/create-user`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ username, email })
      })

      const data = await res.json()

      if (!res.ok) {
        throw new Error(data.error || 'Failed to create user')
      }

      setSuccess(data)
      setUsername('')
      setEmail('')

      // Auto-close after 3 seconds
      setTimeout(() => {
        onClose()
      }, 3000)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-2xl shadow-xl p-6 w-[90%] max-w-md" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-gray-900">Create User</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
            {error}
          </div>
        )}

        {success && (
          <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-lg">
            <div className="text-green-700 font-medium mb-2">✓ {success.message}</div>
            <div className="text-sm text-green-600 space-y-1">
              <div><strong>Username:</strong> {success.user.username}</div>
              <div><strong>Email:</strong> {success.user.email}</div>
              {success.emailSent ? (
                <div className="mt-2 p-2 bg-green-100 rounded">
                  <div className="flex items-center gap-2">
                    <span>📧</span>
                    <span>Login credentials have been sent to the user's email</span>
                  </div>
                </div>
              ) : (
                <div className="mt-2 p-2 bg-yellow-100 rounded">
                  <div className="text-yellow-700 text-xs">
                    <strong>Email failed.</strong> Password: {success.password}
                  </div>
                  <div className="text-xs mt-1">Please share these credentials manually</div>
                </div>
              )}
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-xl border-gray-300 bg-gray-50 px-4 py-2 focus:ring-2 focus:ring-primary focus:border-transparent"
              placeholder="Enter username"
              required
              disabled={loading || success}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-xl border-gray-300 bg-gray-50 px-4 py-2 focus:ring-2 focus:ring-primary focus:border-transparent"
              placeholder="user@example.com"
              required
              disabled={loading || success}
            />
          </div>

          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 rounded-xl border border-gray-300 text-gray-700 hover:bg-gray-50 transition-colors"
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 rounded-xl bg-primary text-white hover:bg-primary-dark transition-colors disabled:opacity-50"
              disabled={loading || success}
            >
              {loading ? 'Creating...' : 'Create User'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function ViewUsersModal({ onClose, token }) {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [error, setError] = useState(null)

  useEffect(() => {
    fetchUsers()
  }, [])

  const fetchUsers = async () => {
    try {
      setLoading(true)
      const r = await fetch(`${API}/api/admin/users`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (!r.ok) throw new Error('Failed to fetch users')
      const data = await r.json()
      setUsers(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const filteredUsers = users.filter(u =>
    u.username.toLowerCase().includes(search.toLowerCase()) ||
    u.email.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-2xl shadow-xl p-6 w-[90%] max-w-2xl h-[80vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-gray-900">Created Users</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="mb-4">
          <input
            type="text"
            placeholder="Search users..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-xl border-gray-300 bg-gray-50 px-4 py-2 focus:ring-2 focus:ring-primary focus:border-transparent"
          />
        </div>

        {error && (
          <div className="bg-red-50 text-red-600 p-3 rounded-xl text-sm mb-4">
            {error}
          </div>
        )}

        <div className="flex-1 overflow-y-auto min-h-0">
          {loading ? (
            <div className="flex justify-center py-8">
              <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
            </div>
          ) : filteredUsers.length === 0 ? (
            <div className="text-center text-gray-500 py-8">No users found</div>
          ) : (
            <div className="grid gap-3">
              {filteredUsers.map(u => (
                <div key={u._id} className="flex items-center gap-3 p-3 rounded-xl bg-gray-50 border border-gray-100">
                  <div className="w-10 h-10 rounded-full bg-indigo-100 text-indigo-700 grid place-items-center font-bold">
                    {u.username.charAt(0).toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-gray-900 truncate">{u.username}</div>
                    <div className="text-sm text-gray-500 truncate">{u.email}</div>
                  </div>
                  <div className="text-xs text-gray-400">
                    {dayjs(u.createdAt).format('MMM D, YYYY')}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ChangePasswordModal({ token, onComplete }) {
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    console.log('ChangePasswordModal mounted');
  }, []);

  // Password validation checks
  const passwordChecks = useMemo(() => ({
    length: newPassword.length >= 8,
    uppercase: /[A-Z]/.test(newPassword),
    lowercase: /[a-z]/.test(newPassword),
    number: /[0-9]/.test(newPassword)
  }), [newPassword])

  const allPasswordChecksPassed = Object.values(passwordChecks).every(Boolean)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    if (!allPasswordChecksPassed) {
      setError('Please meet all password requirements')
      return
    }

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setLoading(true)
    try {
      const r = await fetch(`${API}/api/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ newPassword })
      })

      const data = await r.json()

      if (!r.ok) {
        throw new Error(data.error || 'Failed to update password')
      }

      onComplete(data.user)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-[100]">
      <div className="bg-white rounded-2xl shadow-xl p-8 w-[90%] max-w-md">
        <div className="text-center mb-6">
          <div className="w-16 h-16 bg-yellow-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-gray-900">Change Password Required</h2>
          <p className="text-gray-600 mt-2">For your security, please update your temporary password to continue.</p>
        </div>

        {error && (
          <div className="bg-red-50 text-red-600 p-3 rounded-xl text-sm mb-4 text-center">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full rounded-xl border-gray-300 bg-gray-50 px-4 py-2 focus:ring-2 focus:ring-primary focus:border-transparent"
              placeholder="Min. 8 characters"
              required
            />
          </div>

          {/* Password validation timeline */}
          {newPassword && (
            <div className="bg-sky-50 rounded-xl p-3 space-y-2">
              <div className="text-xs font-medium text-gray-600 mb-2">Password Requirements:</div>
              <div className="space-y-1.5">
                <div className={`flex items-center gap-2 text-xs ${passwordChecks.length ? 'text-green-600' : 'text-gray-500'}`}>
                  <span className={`w-4 h-4 rounded-full flex items-center justify-center ${passwordChecks.length ? 'bg-green-500' : 'bg-gray-300'}`}>
                    {passwordChecks.length ? '✓' : '○'}
                  </span>
                  <span>At least 8 characters</span>
                </div>
                <div className={`flex items-center gap-2 text-xs ${passwordChecks.uppercase ? 'text-green-600' : 'text-gray-500'}`}>
                  <span className={`w-4 h-4 rounded-full flex items-center justify-center ${passwordChecks.uppercase ? 'bg-green-500' : 'bg-gray-300'}`}>
                    {passwordChecks.uppercase ? '✓' : '○'}
                  </span>
                  <span>One uppercase letter (A-Z)</span>
                </div>
                <div className={`flex items-center gap-2 text-xs ${passwordChecks.lowercase ? 'text-green-600' : 'text-gray-500'}`}>
                  <span className={`w-4 h-4 rounded-full flex items-center justify-center ${passwordChecks.lowercase ? 'bg-green-500' : 'bg-gray-300'}`}>
                    {passwordChecks.lowercase ? '✓' : '○'}
                  </span>
                  <span>One lowercase letter (a-z)</span>
                </div>
                <div className={`flex items-center gap-2 text-xs ${passwordChecks.number ? 'text-green-600' : 'text-gray-500'}`}>
                  <span className={`w-4 h-4 rounded-full flex items-center justify-center ${passwordChecks.number ? 'bg-green-500' : 'bg-gray-300'}`}>
                    {passwordChecks.number ? '✓' : '○'}
                  </span>
                  <span>One number (0-9)</span>
                </div>
              </div>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Confirm Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full rounded-xl border-gray-300 bg-gray-50 px-4 py-2 focus:ring-2 focus:ring-primary focus:border-transparent"
              placeholder="Re-enter password"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading || !allPasswordChecksPassed}
            className="w-full bg-primary hover:bg-primary-dark text-white rounded-xl py-3 font-semibold transition-colors disabled:opacity-50 mt-4"
          >
            {loading ? 'Updating Password...' : 'Update Password & Login'}
          </button>
        </form>
      </div>
    </div>
  )
}

function RightPanel({ user, onOpenProfile }) {
  const { token, setConversations, setActiveId, notifications, clearNotifications } = useStore()
  const [users, setUsers] = useState([])
  const [showCreateUser, setShowCreateUser] = useState(false)
  const [showViewUsers, setShowViewUsers] = useState(false)

  useEffect(() => {
    (async () => {
      const r = await fetch(`${API}/api/users`)
      const list = await r.json()
      // Show only 5 newest users
      const filtered = list.filter(u => String(u._id) !== String(user._id))
      const sorted = filtered.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
      setUsers(sorted.slice(0, 5))
    })()
  }, [user._id])

  const startDirect = async (id) => {
    const r = await fetch(`${API}/api/conversations/direct`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ userId: id }) })
    const conv = await r.json()
    setConversations(cs => (cs.find(c => c._id === conv._id) ? cs : [conv, ...cs]))
    setActiveId(conv._id)
  }

  return (
    <div className="h-full bg-sky-50/40 p-4">
      <div className="h-full bg-white rounded-2xl shadow-soft p-4 overflow-y-auto">
        <ProfileCard user={user} onOpenProfile={onOpenProfile} />

        {/* Admin: Create & View User Buttons */}
        {user.isAdmin && (
          <div className="mt-4 mb-4 space-y-2">
            <button
              onClick={() => setShowCreateUser(true)}
              className="w-full bg-primary hover:bg-primary-dark text-white rounded-xl px-4 py-2.5 font-medium transition-colors flex items-center justify-center gap-2"
            >
              <span className="material-icons">person_add</span>
              <span>Create User</span>
            </button>
            <button
              onClick={() => setShowViewUsers(true)}
              className="w-full bg-white border border-gray-200 hover:bg-gray-50 text-gray-700 rounded-xl px-4 py-2.5 font-medium transition-colors flex items-center justify-center gap-2"
            >
              <span className="material-icons">group</span>
              <span>View Users</span>
            </button>
          </div>
        )}

        <div className="flex items-center justify-between mb-3 mt-4">
          <div className="font-semibold">Notification</div>
          {notifications && notifications.length > 0 && (
            <button
              onClick={clearNotifications}
              className="text-[11px] text-gray-500 hover:text-gray-700"
            >
              Clear
            </button>
          )}
        </div>
        <div className="space-y-3 text-sm text-gray-600 mb-6">
          {(!notifications || notifications.length === 0) && (
            <>
              <div className="flex items-start gap-3">
                <div className="w-8 h-8 rounded-full bg-gray-200"></div>
                <div>Welcome! Start a chat from the left panel.</div>
              </div>
              <div className="flex items-start gap-3">
                <div className="w-8 h-8 rounded-full bg-gray-200"></div>
                <div>You can start <b>audio</b> or <b>video</b> calls from the chat header.</div>
              </div>
            </>
          )}
          {notifications && notifications.map(n => (
            <button
              key={n.id}
              onClick={() => setActiveId(n.conversationId)}
              className="w-full text-left flex items-start gap-3 px-2 py-2 rounded-xl hover:bg-sky-50 border border-sky-50"
            >
              <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 grid place-items-center text-xs font-semibold">
                {(n.title || 'N').charAt(0).toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <div className="font-medium text-xs truncate">{n.title}</div>
                  {n.createdAt && (
                    <div className="text-[10px] text-gray-400 whitespace-nowrap">
                      {dayjs(n.createdAt).format('HH:mm')}
                    </div>
                  )}
                </div>
                <div className="text-[11px] text-gray-500 truncate">
                  {n.from && <span className="font-medium mr-1">{n.from}:</span>}
                  <span>{n.message}</span>
                </div>
              </div>
            </button>
          ))}
        </div>
        <div className="font-semibold mb-3">Suggestions</div>
        <div className="space-y-2">
          {users.map(u => (
            <div key={u._id} className="flex items-center justify-between bg-sky-50 rounded-xl px-3 py-2">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 grid place-items-center font-semibold">{u.username?.charAt(0)?.toUpperCase()}</div>
                <div className="text-sm">{u.username}</div>
              </div>
              <button onClick={() => startDirect(u._id)} className="text-xs bg-primary text-white rounded-lg px-3 py-1">Add</button>
            </div>
          ))}
          {users.length === 0 && (<div className="text-xs text-gray-500">No suggestions</div>)}
        </div>
      </div>

      {/* Create User Modal */}
      {showCreateUser && (
        <CreateUserModal
          onClose={() => setShowCreateUser(false)}
          token={token}
        />
      )}

      {/* View Users Modal */}
      {showViewUsers && (
        <ViewUsersModal
          onClose={() => setShowViewUsers(false)}
          token={token}
        />
      )}
    </div>
  )
}

function ProfileCard({ user, onOpenProfile }) {
  // Current user is always online
  return (
    <div className="bg-sky-50/60 rounded-2xl p-3 mb-2">
      <div className="flex items-center gap-3">
        <div className="w-12 h-12 rounded-full border bg-indigo-100 text-indigo-700 grid place-items-center font-semibold">{user.username?.charAt(0)?.toUpperCase()}</div>
        <div className="flex-1">
          <div className="font-semibold">{user.username}</div>
          <div className="text-xs text-green-600 flex items-center gap-1">
            <span className="w-2 h-2 bg-green-600 rounded-full"></span>
            <span>Online</span>
          </div>
        </div>
        <button onClick={onOpenProfile} className="text-xs bg-primary text-white rounded-lg px-3 py-1">View</button>
      </div>
    </div>
  )
}

function ProfileModal({ user, onClose, onLogout }) {
  const { token, setUser } = useStore()
  const [edit, setEdit] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [form, setForm] = useState({
    username: user.username || '',
    email: user.email || '',
    phone: user.phone || '',
    address: user.address || '',
    avatar: user.avatar || ''
  })

  // Sync form with user updates
  useEffect(() => {
    setForm({
      username: user.username || '',
      email: user.email || '',
      phone: user.phone || '',
      address: user.address || '',
      avatar: user.avatar || ''
    })
  }, [user])

  const save = async () => {
    try {
      setLoading(true)
      setError(null)

      const r = await fetch(`${API}/api/users/me`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(form)
      });

      const data = await r.json()

      if (!r.ok) {
        throw new Error(data.error || 'Failed to update profile')
      }

      // Update user in global state
      const updatedUser = { ...user, ...data }
      setUser(updatedUser)

      // Close edit mode
      setEdit(false)

      // Show success message
      alert('Profile updated successfully!')

    } catch (err) {
      console.error('Error saving profile:', err)
      setError(err.message || 'Failed to update profile. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50">
      <div className="w-[520px] bg-white rounded-2xl shadow-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="font-semibold text-lg">My Profile</div>
          <button onClick={onClose} className="text-gray-500">✕</button>
        </div>
        <div className="flex flex-col items-center text-center mb-4">
          <div className="w-24 h-24 rounded-full border mb-3 bg-indigo-100 text-indigo-700 grid place-items-center text-3xl font-bold">{(form.username || user.username || '?').charAt(0).toUpperCase()}</div>
          {!edit ? (
            <>
              <div className="text-lg font-semibold">{user.username}</div>
              <div className="text-xs text-green-600 mt-1 flex items-center justify-center gap-1">
                <span className="w-2 h-2 bg-green-600 rounded-full"></span>
                <span>Online</span>
              </div>
            </>
          ) : (
            <input value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} className="rounded-xl border-0 bg-sky-50 px-3 py-2" />
          )}
        </div>
        {error && (
          <div className="bg-red-50 text-red-700 p-3 rounded-lg text-sm mb-4">
            {error}
          </div>
        )}
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="bg-sky-50/60 rounded-xl p-3">
            <div className="text-gray-500">Email</div>
            {!edit ? <div className="font-medium">{user.email || 'Not set'}</div> : <input value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} className="w-full rounded-lg border-0 bg-white px-2 py-1" />}
          </div>
          <div className="bg-sky-50/60 rounded-xl p-3">
            <div className="text-gray-500">Phone</div>
            {!edit ? <div className="font-medium">{user.phone || 'Not set'}</div> : <input value={form.phone} onChange={e => setForm({ ...form, phone: e.target.value })} className="w-full rounded-lg border-0 bg-white px-2 py-1" />}
          </div>
          <div className="bg-sky-50/60 rounded-xl p-3">
            <div className="text-gray-500">Address</div>
            {!edit ? <div className="font-medium">{user.address || 'Not set'}</div> : <input value={form.address} onChange={e => setForm({ ...form, address: e.target.value })} className="w-full rounded-lg border-0 bg-white px-2 py-1" />}
          </div>


          <div className="bg-sky-50/60 rounded-xl p-3">
            <div className="text-gray-500">Joined</div>
            <div className="font-medium">{dayjs(user.createdAt || new Date()).format('DD MMM YYYY')}</div>
          </div>
        </div>
        <div className="mt-6 flex justify-between">
          {!edit ? (
            <>
              <button onClick={() => setEdit(true)} className="px-4 py-2 rounded-lg bg-primary text-white">Edit profile</button>
              <div className="space-x-2">
                <button onClick={onClose} className="px-4 py-2 rounded-lg bg-gray-100">Close</button>
                <button onClick={onLogout} className="px-4 py-2 rounded-lg bg-red-500 text-white">Logout</button>
              </div>
            </>
          ) : (
            <>
              <button onClick={save} disabled={loading} className="px-4 py-2 rounded-lg bg-primary text-white disabled:opacity-50">
                {loading ? 'Saving...' : 'Save'}
              </button>
              <div className="space-x-2">
                <button onClick={() => { setEdit(false); setError(null) }} disabled={loading} className="px-4 py-2 rounded-lg bg-gray-100 disabled:opacity-50">Cancel</button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
