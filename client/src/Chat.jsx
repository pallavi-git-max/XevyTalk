import React, { useEffect, useRef, useState } from 'react'
import EmojiPicker from 'emoji-picker-react'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import { useStore } from './store'
import { createSocket } from './socket'
import NewChatModal from './NewChatModal'
import CallPage from './CallPage'
import { useNavigate } from 'react-router-dom'
import { generateKey, exportKey, importKey, encryptMessage, decryptMessage, isEncrypted } from './crypto'

dayjs.extend(relativeTime)

import API_URL from './config';

const API = API_URL;

const StatusIcon = ({ m, me, totalMembers }) => {
  const others = totalMembers - 1
  const delivered = (m.deliveredTo || []).map(String).filter(id => id !== String(me)).length >= others
  const seen = (m.seenBy || []).map(String).filter(id => id !== String(me)).length >= others
  return (
    <span className="text-xs text-gray-400 ml-2">
      {seen ? '✓✓ Seen' : delivered ? '✓✓ Delivered' : '✓ Sent'}
    </span>
  )
}

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
            ✕
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
  const { token } = useStore()

  useEffect(() => {
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

    fetchMembers()
  }, [conv?._id, token])

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
                className="flex items-center gap-3 bg-sky-50/60 hover:bg-sky-100/60 rounded-xl p-3 transition-colors"
              >
                <div className="w-10 h-10 rounded-full bg-indigo-100 text-indigo-700 grid place-items-center font-semibold text-lg flex-shrink-0">
                  {member.username?.charAt(0)?.toUpperCase()}
                </div>
                <div className="min-w-0">
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
              </div>
            ))}
          </div>
        )}

        <div className="mt-6 pt-4 border-t">
          <button
            onClick={onClose}
            className="w-full bg-primary text-white py-2 px-4 rounded-lg hover:bg-primary/90 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
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
  const [socket, setSocket] = useState(null)
  const [typingUsers, setTypingUsers] = useState({})
  const [openNew, setOpenNew] = useState(false)
  const [selectedMessage, setSelectedMessage] = useState(null)
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
        const convId = String(msg.conversation)
        const senderId = String(msg.sender?._id || msg.sender)
        const myId = user?._id ? String(user._id) : ''
        if (senderId === myId && msg.tempId) {
          replaceTempMessage(convId, msg.tempId, msg)
        } else {
          pushMessage(convId, msg)
        }
        // Update lastMessageAt so lists can sort by recent activity
        setConversations(cs => cs.map(c => c._id === convId ? { ...c, lastMessageAt: msg.createdAt || c.lastMessageAt || new Date().toISOString() } : c))
        const state = useStore.getState()
        const isFromMe = senderId === myId
        const isActive = String(state.activeId || '') === convId
        if (!isFromMe && !isActive) {
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
        const state = useStore.getState()
        const convId = Object.keys(state.messages).find(cid => (state.messages[cid] || []).some(m => m._id === messageId))
        if (convId) state.updateMessage(convId, messageId, { deliveredTo, seenBy })
      })
      s.on('message_deleted', ({ messageId, conversationId }) => {
        removeMessage(conversationId, messageId)
        if (selectedMessage?._id === messageId) setSelectedMessage(null)
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
        filtered.forEach(c => s.emit('join_conversation', c._id))
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

  const refreshMessages = async () => {
    if (!socket || !activeId || !user || !token) return
    const r = await fetch(`${API}/api/messages/${activeId}`, { headers: { Authorization: `Bearer ${token}` } })
    const msgs = await r.json()
    setMessages(activeId, msgs)
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
        <div className="flex items-center gap-4 text-gray-500">
          <span>📁</span><span>✉️</span><span>🔔</span><span>⚙️</span>
          <input className="rounded-xl border-0 bg-white shadow-soft px-3 py-1 text-sm" placeholder="Search" />
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
            selectedMessage={selectedMessage}
            setSelectedMessage={setSelectedMessage}
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
  const { leftTab, setLeftTab, unreadCounts } = useStore()
  const tab = leftTab
  const [q, setQ] = useState('')
  const sorted = [...conversations].sort((a, b) => {
    const ta = new Date(a.lastMessageAt || a.updatedAt || a.createdAt || 0).getTime()
    const tb = new Date(b.lastMessageAt || b.updatedAt || b.createdAt || 0).getTime()
    return tb - ta
  })

  const list = sorted.filter(c => {
    if (tab === 'direct' && c.type !== 'direct') return false
    if (tab === 'group' && c.type !== 'group') return false
    if (c.type === 'group' && (c.name || '').toLowerCase() === 'lobby') return false
    const name = c.type === 'group' ? (c.name || 'Group') : (c.members.find(m => m._id !== user._id)?.username || 'Direct')
    return name.toLowerCase().includes(q.toLowerCase())
  })

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
        <button onClick={onNew} className="text-xs bg-primary text-white rounded-lg px-2 py-1">New</button>
      </div>
      <div className="grid grid-cols-2 text-xs bg-white rounded-xl shadow-soft overflow-hidden mb-3">
        {['Direct', 'Group'].map((t) => {
          const key = t.toLowerCase()
          const active = tab === key
          const hasUnread = key === 'direct' ? directUnread > 0 : groupUnread > 0
          return (
            <button key={t} onClick={() => setLeftTab(key)} className={`py-2 relative ${active ? 'bg-primary text-white' : 'text-gray-600'}`}>
              {t}
              {hasUnread && (
                <span className="absolute top-1 right-2 w-2 h-2 bg-red-500 rounded-full"></span>
              )}
            </button>
          )
        })}
      </div>
      <div className="mb-2">
        <input value={q} onChange={(e) => setQ(e.target.value)} className="w-full rounded-xl border-0 bg-white shadow-soft px-3 py-2 text-sm" placeholder="Search" />
      </div>
      <div className="space-y-2 overflow-y-auto h-[calc(100%-140px)] pr-2">
        {list.map(c => {
          const other = c.type === 'group' ? null : c.members.find(m => m._id !== user._id)
          const isOnline = other && dayjs().diff(dayjs(other.lastSeenAt), 'minute') < 5
          const unread = (unreadCounts || {})[c._id] || 0

          return (
            <button key={c._id} onClick={() => onPick(c._id)} className={`w-full text-left bg-white rounded-xl px-3 py-2 shadow-soft hover:shadow ${activeId === c._id ? 'ring-2 ring-primary/50' : ''}`}>
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-indigo-100 text-indigo-700 grid place-items-center font-semibold">
                  {c.type === 'group' ? (c.name?.charAt(0) || 'G') : (other?.username?.charAt(0) || 'D')}
                </div>
                <div className="flex-1 flex items-center justify-between">
                  <div>
                    <div className="font-medium text-sm">{c.type === 'group' ? c.name : (other?.username || 'Direct')}</div>
                    {c.type !== 'group' && isOnline && (
                      <div className="text-[10px] text-green-600 flex items-center gap-1">
                        <span className="w-1.5 h-1.5 bg-green-600 rounded-full"></span>
                        <span>Online</span>
                      </div>
                    )}
                  </div>
                  {unread > 0 && (
                    <div className="ml-2 min-w-[18px] px-1 py-0.5 rounded-full bg-red-500 text-white text-[10px] text-center">
                      {unread > 9 ? '9+' : unread}
                    </div>
                  )}
                </div>
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

function CenterPanel({ user, socket, typingUsers, setShowMembers, setInfoMsg, refreshMessages, onStartCall, selectedMessage, setSelectedMessage }) {
  const { activeId, messages, pushMessage, token, setEncryptionKey, getEncryptionKey } = useStore()
  const [text, setText] = useState('')
  const [showCallMenu, setShowCallMenu] = useState(false)
  const [showEmoji, setShowEmoji] = useState(false)
  const listRef = useRef(null)
  const fileInputRef = useRef(null)
  const convMessages = activeId ? (messages[activeId] || []) : []

  const conv = useStore.getState().conversations.find(c => c._id === activeId)
  const membersCount = conv?.members?.length || 1
  const other = conv?.members?.find(m => String(m._id) !== String(user._id))

  useEffect(() => {
    listRef.current?.lastElementChild?.scrollIntoView({ behavior: 'smooth' })
  }, [convMessages.length])

  const handleSend = async () => {
    if (!text.trim() || !socket || !activeId) return

    const tempId = Math.random().toString(36).slice(2)
    const msg = {
      _id: tempId,
      tempId,
      conversation: activeId,
      sender: user,
      content: text,
      createdAt: new Date().toISOString(),
      deliveredTo: [],
      seenBy: []
    }
    pushMessage(activeId, msg)

    // Send plain text to server (server will handle encryption at rest)
    socket.emit('message_send', {
      conversationId: activeId,
      content: text,
      tempId
    })

    setText('')
    socket.emit('stop_typing', { conversationId: activeId })
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

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return

    const formData = new FormData()
    formData.append('file', file)

    try {
      const res = await fetch(`${API}/api/upload`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      })
      if (!res.ok) throw new Error('Upload failed')
      const attachment = await res.json()

      const tempId = Math.random().toString(36).slice(2)
      const msg = {
        _id: tempId,
        tempId,
        conversation: activeId,
        sender: user,
        content: '',
        attachments: [attachment],
        createdAt: new Date().toISOString(),
        deliveredTo: [],
        seenBy: []
      }
      pushMessage(activeId, msg)
      socket.emit('message_send', { conversationId: activeId, content: '', tempId, attachments: [attachment] })
    } catch (e) {
      console.error(e)
      alert('Failed to upload file')
    }
    // Reset input
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

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
      <div className="px-5 py-3 border-b flex items-center justify-between relative h-16">
        {selectedMessage ? (
          <>
            <div className="flex items-center gap-3">
              <button onClick={() => setSelectedMessage(null)} className="p-2 hover:bg-gray-100 rounded-full">✕</button>
              <div className="font-semibold text-sm">1 selected</div>
            </div>
            <div className="flex items-center gap-3">
              <button onClick={() => { setInfoMsg(selectedMessage); setSelectedMessage(null) }} className="p-2 hover:bg-gray-100 rounded-lg" title="Info">ℹ️</button>
              {String(selectedMessage.sender?._id || selectedMessage.sender) === String(user._id) && (
                <button
                  onClick={async () => {
                    if (!confirm('Delete this message?')) return
                    try {
                      await fetch(`${API}/api/messages/${selectedMessage._id}`, {
                        method: 'DELETE',
                        headers: { Authorization: `Bearer ${token}` }
                      })
                      setSelectedMessage(null)
                    } catch (e) {
                      console.error(e)
                      alert('Failed to delete')
                    }
                  }}
                  className="p-2 hover:bg-red-50 text-red-600 rounded-lg"
                  title="Delete"
                >
                  🗑️
                </button>
              )}
            </div>
          </>
        ) : (
          <>
            <div>
              <div className="font-semibold">{conv?.type === 'group' ? (conv?.name || 'Group') : (other?.username || 'Conversation')}</div>
              {other && (
                <div className="text-xs flex items-center gap-1">
                  {/* Show online if last seen within 5 minutes */}
                  {dayjs().diff(dayjs(other.lastSeenAt), 'minute') < 5 ? (
                    <>
                      <span className="w-2 h-2 bg-green-600 rounded-full"></span>
                      <span className="text-green-600">Online</span>
                    </>
                  ) : (
                    <span className="text-gray-500">Last seen {dayjs(other.lastSeenAt).fromNow?.() || dayjs(other.lastSeenAt).format('HH:mm')}</span>
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
                      <span>📞</span>
                    </button>
                    {showCallMenu && (
                      <div className="absolute right-0 mt-1 w-44 bg-white rounded-xl shadow-lg border text-sm z-10">
                        <button
                          className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-50 text-left"
                          onClick={() => { setShowCallMenu(false); onStartCall('video') }}
                        >
                          <span className="text-base">🎥</span>
                          <span>Video call</span>
                        </button>
                        <button
                          className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-50 text-left"
                          onClick={() => { setShowCallMenu(false); onStartCall('audio') }}
                        >
                          <span className="text-base">📞</span>
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
                🔄
              </button>
              {conv?.type === 'group' && (
                <button title="Group Info" className="p-2 rounded-lg hover:bg-gray-100" onClick={() => setShowMembers(true)}>ℹ️</button>
              )}
            </div>
          </>
        )}
      </div>
      <div ref={listRef} className="flex-1 overflow-y-auto p-6 space-y-3 bg-sky-50/40">
        {convMessages.length === 0 && null}
        {convMessages.map(m => (
          <MessageBubble
            key={m._id}
            me={user._id}
            m={m}
            totalMembers={membersCount}
            conv={conv}
            onInfo={() => setInfoMsg(m)}
            selected={selectedMessage?._id === m._id}
            onSelect={() => setSelectedMessage(selectedMessage?._id === m._id ? null : m)}
          />
        ))}
        {isTyping && <div className="text-xs text-gray-500">Typing...</div>}
      </div>
      <div className="p-4 border-t bg-white">
        <div className="flex items-center gap-2">
          <div className="relative">
            <button onClick={() => setShowEmoji(!showEmoji)} className="px-3 py-2 rounded-lg bg-gray-100" title="Emoji">😊</button>
            {showEmoji && (
              <div className="absolute bottom-12 left-0 z-10">
                <EmojiPicker onEmojiClick={handleEmojiClick} />
              </div>
            )}
          </div>
          <button onClick={() => fileInputRef.current?.click()} className="px-3 py-2 rounded-lg bg-gray-100" title="Attach">📎</button>
          <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileUpload} />
          <input value={text} onChange={(e) => onInput(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') handleSend() }} className="flex-1 rounded-full border-0 bg-sky-50 px-4 py-3" placeholder="Say something..." />
          <button onClick={handleSend} className="bg-primary text-white px-4 py-3 rounded-full">Send</button>
        </div>
      </div>
    </div>
  )
}

function MessageBubble({ m, me, totalMembers, conv, onInfo, selected, onSelect }) {
  const mine = String(m.sender?._id || m.sender) === String(me)
  const senderName = m.sender?.username || (conv?.members || []).find(x => String(x._id) === String(m.sender))?.username || (mine ? 'You' : 'User')
  return (
    <div className={`flex ${mine ? 'justify-end' : 'justify-start'}`}>
      <div
        onClick={onSelect}
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
        <div className="text-sm whitespace-pre-wrap">{m.content}</div>
        <div className={`text-[10px] mt-1 flex items-center gap-2 ${mine ? 'text-white/80' : 'text-gray-500'}`}>
          <span>{dayjs(m.createdAt).format('HH:mm')}</span>
          {mine && <StatusIcon m={m} me={me} totalMembers={totalMembers} />}
          <button onClick={onInfo} className={`ml-1 ${mine ? 'text-white/80' : 'text-gray-400'} hover:underline`}>info</button>
        </div>
      </div>
    </div>
  )
}

function RightPanel({ user, onOpenProfile }) {
  const { token, setConversations, setActiveId, notifications, clearNotifications } = useStore()
  const [users, setUsers] = useState([])
  useEffect(() => {
    (async () => {
      const r = await fetch(`${API}/api/users`)
      const list = await r.json()
      setUsers(list.filter(u => String(u._id) !== String(user._id)))
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
