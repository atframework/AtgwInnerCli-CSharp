using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace atframe.gw.inner
{
    /// <summary>
    /// Client protocol context wrapper for atgateway
    /// </summary>
    public class ClientProtocol
    {
        #region error code
        public enum error_code_t : int
        {
            EN_ECT_SUCCESS = 0,
            EN_ECT_FIRST_IDEL = -1001,
            EN_ECT_HANDSHAKE = -1002,
            EN_ECT_BUSY = -1003,
            EN_ECT_SESSION_EXPIRED = -1004,
            EN_ECT_REFUSE_RECONNECT = -1005,
            EN_ECT_MISS_CALLBACKS = -1006,
            EN_ECT_INVALID_ROUTER = -1007,
            EN_ECT_INVALID_ADDRESS = -1008,
            EN_ECT_NETWORK = -1009,
            EN_ECT_BAD_PROTOCOL = -1010,
            EN_ECT_CLOSING = -1011,
            EN_ECT_LOST_MANAGER = -1012,
            EN_ECT_MSG_TOO_LARGE = -1013,
            EN_ECT_HANDLE_NOT_FOUND = -1014,
            EN_ECT_ALREADY_HAS_FD = -1015,
            EN_ECT_SESSION_NOT_FOUND = -1016,
            EN_ECT_SESSION_ALREADY_EXIST = -1017,
            EN_ECT_NOT_WRITING = -1018,
            EN_ECT_CRYPT_NOT_SUPPORTED = -1019,
            EN_ECT_PARAM = -1020,
            EN_ECT_BAD_DATA = -1021,
            EN_ECT_INVALID_SIZE = -1022,
            EN_ECT_NO_DATA = -1023,
            EN_ECT_MALLOC = -1024,
            EN_ECT_CRYPT_ALREADY_INITED = -1101,
            EN_ECT_CRYPT_VERIFY = -1102,
            EN_ECT_CRYPT_OPERATION = -1103,
            EN_ECT_CRYPT_READ_DHPARAM_FILE = -1211,
            EN_ECT_CRYPT_INIT_DHPARAM = -1212,
            EN_ECT_CRYPT_READ_RSA_PUBKEY = -1221,
            EN_ECT_CRYPT_READ_RSA_PRIKEY = -1222,
        };
        #endregion

        #region close reason
        public enum close_reason_t : int
        {
            EN_CRT_UNKNOWN = 0x0000,
            EN_CRT_EAGAIN = 0x0001, // resource temporary unavailable
            EN_CRT_TRAFIC_EXTENDED = 0x0002,
            EN_CRT_INVALID_DATA = 0x0003,
            EN_CRT_RESET = 0x0004,
            EN_CRT_RECONNECT_INNER_BOUND = 0x0100,
            EN_CRT_RECONNECT_BOUND = 0x10000,
            EN_CRT_FIRST_IDLE = 0x10001,
            EN_CRT_SERVER_CLOSED = 0x10002,
            EN_CRT_SERVER_BUSY = 0x10003,
            EN_CRT_KICKOFF = 0x10004,
            EN_CRT_HANDSHAKE = 0x10005,
            EN_CRT_LOGOUT = 0x10006,
            EN_CRT_ADMINISTRATOR = 0x10007, // kickoff by administrator
            EN_CRT_MAINTENANCE = 0x10008, // closed to maintenance
            EN_CRT_EOF = 0x10009, // EOF means everything is finished and no more need this connection
            EN_CRT_NO_RECONNECT_INNER_BOUND = 0x10100,
        };
        #endregion

        #region native delegate types
        /// <summary>
        /// Write start delegate function.
        /// This function will be called when there is any data should be write to peer.
        /// </summary>
        /// <param name="context">protocol context</param>
        /// <param name="buffer">the data about to write</param>
        /// <param name="buffer_length">length of buffer</param>
        /// <param name="is_done">is used to tell the protocol handle if this write is finished, if it's a async writing and not finished immediately, 
        /// is_done should be set into 1 and call libatgw_inner_v1_c_write_done when all writings are finished.</param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int libatgw_inner_v1_c_on_write_start_fn_t(IntPtr context, IntPtr buffer, ulong buffer_length, out int is_done);

        /// <summary>
        /// On message delegate function.
        /// This function will be called when there is any full user message received.
        /// </summary>
        /// <param name="context">protocol context</param>
        /// <param name="buffer">the data of the message</param>
        /// <param name="buffer_length">length of the message</param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int libatgw_inner_v1_c_on_message_fn_t(IntPtr context, IntPtr buffer, ulong buffer_length);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int libatgw_inner_v1_c_on_init_new_session_fn_t(IntPtr context, out ulong session_id);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int libatgw_inner_v1_c_on_init_reconnect_fn_t(IntPtr context, ulong session_id);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int libatgw_inner_v1_c_on_close_fn_t(IntPtr context, int reason);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int libatgw_inner_v1_c_on_handshake_done_fn_t(IntPtr context, int status);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int libatgw_inner_v1_c_on_error_fn_t(IntPtr context, IntPtr file_name, int line, int error_code, IntPtr message);


        private struct ProtoCallbacks
        {
            public libatgw_inner_v1_c_on_write_start_fn_t OnWriteStart;
            public libatgw_inner_v1_c_on_message_fn_t OnMessage;
            public libatgw_inner_v1_c_on_init_new_session_fn_t OnInitNewSession;
            public libatgw_inner_v1_c_on_init_reconnect_fn_t OnInitReconnect;
            public libatgw_inner_v1_c_on_close_fn_t OnClose;
            public libatgw_inner_v1_c_on_handshake_done_fn_t OnHandshakeDone;
            public libatgw_inner_v1_c_on_handshake_done_fn_t OnHandshakeUpdate;
            public libatgw_inner_v1_c_on_error_fn_t OnError;
        }
        #endregion

        #region wrapper delegate types
        public delegate int OnWriteDataFunction(ClientProtocol self, byte[] data, ref bool is_done);
        public delegate int OnReceiveMessageFunction(ClientProtocol self, byte[] data);
        public delegate int OnInitNewSessionFunction(ClientProtocol self, out ulong session_id);
        public delegate int OnInitReconnectSessionFunction(ClientProtocol self, ulong session_id);
        public delegate int OnCloseFunction(ClientProtocol self, int reason);
        public delegate int OnHandshakeDoneFunction(ClientProtocol self, int status);
        public delegate int OnErrorFunction(ClientProtocol self, string file_name, int line, int error_code, string message);
        #endregion

        static private readonly Dictionary<IntPtr, ClientProtocol> _binder_manager = new Dictionary<IntPtr, ClientProtocol>();
        static private ProtoCallbacks _shared_callbacks = new ProtoCallbacks();

        #region member datas
        private IntPtr _native_protocol = IntPtr.Zero;
        private IntPtr _last_alloc = IntPtr.Zero;
        public OnWriteDataFunction OnWriteData = null;
        public OnReceiveMessageFunction OnReceiveMessage = null;
        public OnInitNewSessionFunction OnInitNewSession = null;
        public OnInitReconnectSessionFunction OnInitReconnectSession = null;
        public OnCloseFunction OnClose = null;
        public OnHandshakeDoneFunction OnHandshakeDone = null;
        public OnHandshakeDoneFunction OnHandshakeUpdate = null;
        public OnErrorFunction OnError = null;
        #endregion
        public IntPtr NativeProtocol
        {
            get
            {
                if (IntPtr.Zero == _native_protocol)
                {
                    _native_protocol = libatgw_inner_v1_c_create();
                    {
                        // write
                        if (null == _shared_callbacks.OnWriteStart)
                        {
                            IntPtr fn = Marshal.GetFunctionPointerForDelegate(_shared_callbacks.OnWriteStart = new libatgw_inner_v1_c_on_write_start_fn_t(proto_on_write_start_fn));
                            libatgw_inner_v1_c_gset_on_write_start_fn(fn);
                        }

                        // message
                        if (null == _shared_callbacks.OnMessage)
                        {
                            IntPtr fn = Marshal.GetFunctionPointerForDelegate(_shared_callbacks.OnMessage = new libatgw_inner_v1_c_on_message_fn_t(proto_on_message_fn));
                            libatgw_inner_v1_c_gset_on_message_fn(fn);
                        }

                        // new session
                        if (null == _shared_callbacks.OnInitNewSession)
                        {
                            IntPtr fn = Marshal.GetFunctionPointerForDelegate(_shared_callbacks.OnInitNewSession = new libatgw_inner_v1_c_on_init_new_session_fn_t(proto_on_init_new_session_fn));
                            libatgw_inner_v1_c_gset_on_init_new_session_fn(fn);
                        }

                        // reconnect session
                        if (null == _shared_callbacks.OnInitReconnect)
                        {
                            IntPtr fn = Marshal.GetFunctionPointerForDelegate(_shared_callbacks.OnInitReconnect = new libatgw_inner_v1_c_on_init_reconnect_fn_t(proto_on_init_reconnect_fn));
                            libatgw_inner_v1_c_gset_on_init_reconnect_fn(fn);
                        }

                        // on close
                        if (null == _shared_callbacks.OnClose)
                        {
                            IntPtr fn = Marshal.GetFunctionPointerForDelegate(_shared_callbacks.OnClose = new libatgw_inner_v1_c_on_close_fn_t(proto_on_close_fn));
                            libatgw_inner_v1_c_gset_on_close_fn(fn);
                        }

                        // on handshake done
                        if (null == _shared_callbacks.OnHandshakeDone)
                        {
                            IntPtr fn = Marshal.GetFunctionPointerForDelegate(_shared_callbacks.OnHandshakeDone = new libatgw_inner_v1_c_on_handshake_done_fn_t(proto_on_handshake_done_fn));
                            libatgw_inner_v1_c_gset_on_handshake_done_fn(fn);
                        }

                        // on handshake update finished
                        if (null == _shared_callbacks.OnHandshakeUpdate)
                        {
                            IntPtr fn = Marshal.GetFunctionPointerForDelegate(_shared_callbacks.OnHandshakeUpdate = new libatgw_inner_v1_c_on_handshake_done_fn_t(proto_on_handshake_update_fn));
                            libatgw_inner_v1_c_gset_on_handshake_update_fn(fn);
                        }

                        // on error
                        if (null == _shared_callbacks.OnError)
                        {
                            IntPtr fn = Marshal.GetFunctionPointerForDelegate(_shared_callbacks.OnError = new libatgw_inner_v1_c_on_error_fn_t(proto_on_error_fn));
                            libatgw_inner_v1_c_gset_on_error_fn(fn);
                        }
                    }

                    return _native_protocol;
                }

                return _native_protocol;
            }
        }

        public ClientProtocol()
        {
            if (IntPtr.Zero == NativeProtocol)
            {
                throw new System.OutOfMemoryException("Can not create native atgateway inner protocol v1 object");
            }
            else
            {
                lock (_binder_manager)
                {
                    _binder_manager.Add(NativeProtocol, this);
                }
            }
        }

        ~ClientProtocol()
        {
            if (null != _native_protocol)
            {
                libatgw_inner_v1_c_destroy(_native_protocol);
                lock (_binder_manager)
                {
                    _binder_manager.Remove(_native_protocol);
                }
            }
        }

#if !UNITY_EDITOR && UNITY_IPHONE
        const string LIBNAME = "__Internal";
#else
        const string LIBNAME = "atgw_inner_v1_c";
#endif
        #region golbal native functions
        /// <summary>
        /// Initialize global algorithms of cipher and etc.
        /// </summary>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_global_init_algorithms();

        /// <summary>
        /// Get available crypt type number
        /// </summary>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern ulong libatgw_inner_v1_c_global_get_crypt_size();

        /// <summary>
        /// Get available crypt type name at idx
        /// </summary>
        /// <param name="idx">index</param>
        /// <returns>crypt type name</returns>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr libatgw_inner_v1_c_global_get_crypt_name(ulong idx);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_write_start_fn_t of global callback set.
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_write_start_fn_t</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_write_start_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_message_fn_t of global callback set.
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_message_fn_t</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_message_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_init_new_session_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_init_new_session_fn_t</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_init_new_session_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_init_reconnect_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_init_reconnect_fn_t</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_init_reconnect_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_close_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_close_fn_t</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_close_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_handshake_done_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_handshake_done_fn_t</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_handshake_done_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_handshake_done_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_handshake_done_fn_t</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_handshake_update_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_error_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_error_fn_t</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_error_fn(IntPtr fn);

        #endregion

        #region inner delegate functions

        static private ClientProtocol GetClientProtocol(IntPtr key)
        {
            lock (_binder_manager)
            {
                ClientProtocol ret;
                return _binder_manager.TryGetValue(key, out ret) ? ret : null;
            }
        }

        static public int proto_on_write_start_fn(IntPtr context, IntPtr buffer, ulong buffer_length, out int is_done)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                is_done = 1;
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnWriteData)
            {
                byte[] data_buffer = new byte[buffer_length];
                Marshal.Copy(buffer, data_buffer, 0, (int)buffer_length);
                bool is_done_b = false;
                int ret = self.OnWriteData(self, data_buffer, ref is_done_b);
                is_done = is_done_b ? 1 : 0;
                return ret;
            }

            is_done = 1;
            return (int)error_code_t.EN_ECT_MISS_CALLBACKS;
        }

        static public int proto_on_message_fn(IntPtr context, IntPtr buffer, ulong buffer_length)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnReceiveMessage)
            {
                byte[] data_buffer = new byte[buffer_length];
                Marshal.Copy(buffer, data_buffer, 0, (int)buffer_length);
                return self.OnReceiveMessage(self, data_buffer);
            }

            return 0;
        }

        static public int proto_on_init_new_session_fn(IntPtr context, out ulong session_id)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                session_id = 0;
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnInitNewSession)
            {
                session_id = 0;
                return self.OnInitNewSession(self, out session_id);
            }

            session_id = 0;
            return (int)error_code_t.EN_ECT_MISS_CALLBACKS;
        }

        static public int proto_on_init_reconnect_fn(IntPtr context, ulong session_id)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnInitReconnectSession)
            {
                return self.OnInitReconnectSession(self, session_id);
            }

            return (int)error_code_t.EN_ECT_MISS_CALLBACKS;
        }

        static public int proto_on_close_fn(IntPtr context, int reason)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnClose)
            {
                return self.OnClose(self, reason);
            }

            return 0;
        }

        static public int proto_on_handshake_done_fn(IntPtr context, int status)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnHandshakeDone)
            {
                return self.OnHandshakeDone(self, status);
            }

            return 0;
        }

        static public int proto_on_handshake_update_fn(IntPtr context, int status)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnHandshakeUpdate)
            {
                return self.OnHandshakeUpdate(self, status);
            }

            return 0;
        }

        static public int proto_on_error_fn(IntPtr context, IntPtr file_name, int line, int error_code, IntPtr message)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnError)
            {
                return self.OnError(self, Marshal.PtrToStringAnsi(file_name), line, error_code, Marshal.PtrToStringAnsi(message));
            }

            return 0;
        }

        #endregion

        #region import all native methods
        /// <summary>
        /// Create a inner protocol context for atgateway
        /// </summary>
        /// <returns>protocol context for atgateway, null if failed</returns>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr libatgw_inner_v1_c_create();

        /// <summary>
        /// Destroy a inner protocol context for atgateway
        /// </summary>
        /// <param name="ptr">protocol context for atgateway</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_destroy(IntPtr ptr);

        /// <summary>
        /// Set receive buffer limit in the protocol handle
        /// </summary>
        /// <param name="context"></param>
        /// <param name="max_size">max size</param>
        /// <param name="max_number">max message number</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_set_recv_buffer_limit(IntPtr context, ulong max_size, ulong max_number);

        /// <summary>
        /// Set send buffer limit in the protocol handle
        /// </summary>
        /// <param name="context"></param>
        /// <param name="max_size">max size</param>
        /// <param name="max_number">max message number</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_set_send_buffer_limit(IntPtr context, ulong max_size, ulong max_number);

        /// <summary>
        /// Start a session
        /// </summary>
        /// <param name="context"></param>
        /// <returns>0 or error code</returns>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_start_session(IntPtr context, string crypt_type);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_reconnect_session(IntPtr context, ulong sessios_id, string crypt_type,
                                                                           byte[] secret_buf, ulong secret_len);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_get_info(IntPtr context, StringBuilder info_str, ulong info_len);

        /// <summary>
        /// Set private data of specify protocol context
        /// </summary>
        /// <param name="context">protocol context</param>
        /// <param name="data">private data</param>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_set_private_data(IntPtr context, IntPtr data);

        /// <summary>
        /// Get private data of specify protocol context
        /// </summary>
        /// <param name="context"></param>
        /// <returns>private data</returns>
        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr libatgw_inner_v1_c_get_private_data(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern ulong libatgw_inner_v1_c_get_session_id(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr libatgw_inner_v1_c_get_crypt_type(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern ulong libatgw_inner_v1_c_get_crypt_secret_size(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern ulong libatgw_inner_v1_c_copy_crypt_secret(IntPtr context, byte[] secret, ulong available_size);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern uint libatgw_inner_v1_c_get_crypt_keybits(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_read_alloc(IntPtr context, ulong suggested_size, out IntPtr out_buf,
                                                                 out ulong out_len);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_read(IntPtr context, int ssz, IntPtr buff, ulong len, out int errcode);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_write_done(IntPtr context, int status);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_post_msg(IntPtr context, byte[] out_buf, ulong out_len);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_send_ping(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern long libatgw_inner_v1_c_get_ping_delta(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_close(IntPtr context, int reason);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_is_closing(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_is_closed(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_is_handshake_updating(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_is_handshake_done(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_is_writing(IntPtr context);

        [DllImport(LIBNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int libatgw_inner_v1_c_is_in_callback(IntPtr context);

        #endregion

        /// <summary>
        /// Get imformation of protocol handle, it cost a lot and should not be called frequently.
        /// </summary>
        public string Information
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return "";
                }

                StringBuilder sb = new StringBuilder(4096);
                libatgw_inner_v1_c_get_info(native, sb, (ulong)sb.Capacity);
                return sb.ToString();
            }
        }

        public void SetReceiveBufferLimit(ulong max_size, ulong max_number)
        {
            IntPtr native = NativeProtocol;
            if (IntPtr.Zero == native)
            {
                return;
            }

            libatgw_inner_v1_c_set_recv_buffer_limit(native, max_size, max_number);
        }

        public void SetSendBufferLimit(ulong max_size, ulong max_number)
        {
            IntPtr native = NativeProtocol;
            if (IntPtr.Zero == native)
            {
                return;
            }

            libatgw_inner_v1_c_set_send_buffer_limit(native, max_size, max_number);
        }

        /// <summary>
        /// Initialize cipher algorithms, should be called bebore AvailableCryptTypes, StartSession or ReconnectSession
        /// </summary>
        static public void GlobalInitialize() {
            libatgw_inner_v1_c_global_init_algorithms();
        }

        /// <summary>
        /// Initialize cipher algorithms, should be called bebore StartSession or ReconnectSession
        /// </summary>
        static public string[] AvailableCryptTypes
        {
            get
            {
                string[] ret = null;
                ulong sz = libatgw_inner_v1_c_global_get_crypt_size();
                ret = new string[sz];
                ulong real_sz = 0;

                for (ulong idx = 0; idx < sz; ++idx)
                {
                    IntPtr val = libatgw_inner_v1_c_global_get_crypt_name(idx);
                    if (IntPtr.Zero == val)
                    {
                        continue;
                    }

                    ret[real_sz++] = Marshal.PtrToStringAnsi(val);
                }

                return ret;
            }
        }

        public int StartSession(string crypt_type)
        {
            IntPtr native = NativeProtocol;
            if (IntPtr.Zero == native)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            return libatgw_inner_v1_c_start_session(native, crypt_type);
        }

        public int ReconnectSession(ulong session_id, string crypt_type, byte[] secret)
        {
            IntPtr native = NativeProtocol;
            if (IntPtr.Zero == native)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            return libatgw_inner_v1_c_reconnect_session(native, session_id, crypt_type, secret, (ulong)secret.Length);
        }

        public ulong SessionID
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return 0;
                }

                return libatgw_inner_v1_c_get_session_id(native);
            }
        }

        public string CryptType
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return "";
                }

                IntPtr cstr = libatgw_inner_v1_c_get_crypt_type(native);
                if (IntPtr.Zero == cstr)
                {
                    return "";
                }

                return Marshal.PtrToStringAnsi(cstr);
            }
        }

        public byte[] Secret
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return new byte[0];
                }

                ulong secret_len = libatgw_inner_v1_c_get_crypt_secret_size(native);
                byte[] ret = new byte[secret_len];
                libatgw_inner_v1_c_copy_crypt_secret(native, ret, secret_len);
                return ret;
            }
        }

        public uint Keybits
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return 0;
                }

                return libatgw_inner_v1_c_get_crypt_keybits(native);
            }
        }

        /// <summary>
        /// Allocate buffer block to store data
        /// </summary>
        /// <param name="suggest_size">suggest size to allocate, it's 64KB in libuv</param>
        /// <param name="len">allocated buffer length</param>
        /// <returns>allocated buffer address, IntPtr.Zero if failed</returns>
        public IntPtr AllocForRead(ulong suggest_size, out ulong len)
        {
            IntPtr native = NativeProtocol;
            if (IntPtr.Zero == native)
            {
                _last_alloc = IntPtr.Zero;
                len = 0;
                return _last_alloc;
            }

            libatgw_inner_v1_c_read_alloc(native, suggest_size, out _last_alloc, out len);
            return _last_alloc;
        }

        /// <summary>
        /// Mark how much data is already copied into read buffer manager
        /// </summary>
        /// <param name="read_sz">lengtn of read data. read buffer manager will cost len bytes and try to dispatch message. must be smaller than len from OnReadAlloc()</param>
        /// <returns>0 or error code</returns>
        public int ReadDone(ulong read_sz)
        {
            IntPtr native = NativeProtocol;
            if (IntPtr.Zero == native)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (0 == read_sz)
            {
                return 0;
            }

            int ret = 0;
            libatgw_inner_v1_c_read(native, (int)read_sz, _last_alloc, read_sz, out ret);
            return ret;
        }

        /// <summary>
        /// Copy and read data from a byte array. This will copy the read buffer once into the read manager.
        /// </summary>
        /// <param name="buf">data source</param>
        /// <param name="len">data length</param>
        /// <returns>0 or error code</returns>
        public int ReadFrom(byte[] buf, ulong len)
        {
            int ret = 0;
            ulong offset = 0;
            while (offset < len)
            {
                IntPtr alloc_buf;
                ulong alloc_len;
                alloc_buf = AllocForRead(len - offset, out alloc_len);
                if (0 == alloc_len || IntPtr.Zero == alloc_buf)
                {
                    return (int)error_code_t.EN_ECT_MALLOC;
                }

                // just a message or not a full message
                if (alloc_len >= len - offset)
                {
                    Marshal.Copy(buf, (int)offset, alloc_buf, (int)(len - offset));
                    ret = ReadDone(len - offset);
                    offset = len;
                }
                else
                {
                    Marshal.Copy(buf, (int)offset, alloc_buf, (int)alloc_len);
                    ret = ReadDone(alloc_len);
                    offset += alloc_len;
                }

                if (ret < 0)
                {
                    return ret;
                }
            }

            return ret;
        }

        /// <summary>
        /// If OnWriteData set is_done to false, this function should be called when the writing is finished.
        /// </summary>
        /// <param name="status">0 or error code</param>
        /// <returns></returns>
        public int NotifyWriteDone(int status)
        {
            IntPtr native = NativeProtocol;
            if (IntPtr.Zero == native)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            return libatgw_inner_v1_c_write_done(native, status);
        }

        public int PostMessage(byte[] buf)
        {
            IntPtr native = NativeProtocol;
            if (IntPtr.Zero == native)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null == buf || 0 == buf.Length)
            {
                return 0;
            }

            return libatgw_inner_v1_c_post_msg(native, buf, (ulong)buf.Length);
        }

        public int SendPing()
        {
            IntPtr native = NativeProtocol;
            if (IntPtr.Zero == native)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            return libatgw_inner_v1_c_send_ping(native);
        }

        public long LastPingDelta
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return 0;
                }

                return libatgw_inner_v1_c_get_ping_delta(native);
            }
        }

        public int Close(int reason = (int)close_reason_t.EN_CRT_UNKNOWN)
        {
            IntPtr native = NativeProtocol;
            if (IntPtr.Zero == native)
            {
                return (int)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            return libatgw_inner_v1_c_close(native, reason);
        }

        public bool IsClosing
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return false;
                }

                return 0 != libatgw_inner_v1_c_is_closing(native);
            }
        }

        public bool IsClosed
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return false;
                }

                return 0 != libatgw_inner_v1_c_is_closed(native);
            }
        }

        public bool IsHandshakeUpdating
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return false;
                }

                return 0 != libatgw_inner_v1_c_is_handshake_updating(native);
            }
        }

        public bool IsHandshakeDone
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return false;
                }

                return 0 != libatgw_inner_v1_c_is_handshake_done(native);
            }
        }

        public bool IsWriting
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return false;
                }

                return 0 != libatgw_inner_v1_c_is_writing(native);
            }
        }

        public bool IsInCallback
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (IntPtr.Zero == native)
                {
                    return false;
                }

                return 0 != libatgw_inner_v1_c_is_in_callback(native);
            }
        }
    }
}
