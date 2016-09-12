using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace atframe.gw.inner {
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
            EN_ECT_CRYPT_READ_DHPARAM_FILE = -1211,
            EN_ECT_CRYPT_INIT_DHPARAM = -1212,
            EN_ECT_CRYPT_READ_RSA_PUBKEY = -1221,
            EN_ECT_CRYPT_READ_RSA_PRIKEY = -1222,
        };
        #endregion

        #region close reason
        public enum close_reason_t : int
        {
            EN_CRT_UNKNOWN = 0,
            EN_CRT_LOGOUT = 1,
            EN_CRT_TRAFIC_EXTENDED = 2,
            EN_CRT_INVALID_DATA = 3,
            EN_CRT_RESET = 4,
            EN_CRT_RECONNECT_BOUND = 1000,
            EN_CRT_FIRST_IDLE = 1001,
            EN_CRT_SERVER_CLOSED = 1002,
            EN_CRT_SERVER_BUSY = 1003,
            EN_CRT_KICKOFF = 1004,
            EN_CRT_HANDSHAKE = 1005,
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
        private delegate Int32 libatgw_inner_v1_c_on_write_start_fn_t(IntPtr context, IntPtr buffer, UInt64 buffer_length, [Out] Int32 is_done);

        /// <summary>
        /// On message delegate function.
        /// This function will be called when there is any full user message received.
        /// </summary>
        /// <param name="context">protocol context</param>
        /// <param name="buffer">the data of the message</param>
        /// <param name="buffer_length">length of the message</param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Int32 libatgw_inner_v1_c_on_message_fn_t(IntPtr context, IntPtr buffer, UInt64 buffer_length);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Int32 libatgw_inner_v1_c_on_init_new_session_fn_t(IntPtr context, [Out] UInt64 session_id);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Int32 libatgw_inner_v1_c_on_init_reconnect_fn_t(IntPtr context, UInt64 session_id);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Int32 libatgw_inner_v1_c_on_close_fn_t(IntPtr context, Int32 reason);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Int32 libatgw_inner_v1_c_on_handshake_done_fn_t(IntPtr context, Int32 status);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Int32 libatgw_inner_v1_c_on_error_fn_t(IntPtr context, IntPtr file_name, Int32 line, Int32 error_code, IntPtr message);

        #endregion

        #region wrapper delegate types
        public delegate Int32 OnWriteDataFunction(ClientProtocol self, byte[] data, [Out] bool is_done);
        public delegate Int32 OnReceiveMessageFunction(ClientProtocol self, byte[] data);
        public delegate Int32 OnInitNewSessionFunction(ClientProtocol self, [Out] UInt64 session_id);
        public delegate Int32 OnInitReconnectSessionFunction(ClientProtocol self, UInt64 session_id);
        public delegate Int32 OnCloseFunction(ClientProtocol self, Int32 reason);
        public delegate Int32 OnHandshakeDoneFunction(ClientProtocol self, Int32 status);
        public delegate Int32 OnErrorFunction(ClientProtocol self, String file_name, Int32 line, Int32 error_code, String message);
        #endregion

        static private readonly Dictionary<IntPtr, ClientProtocol> _binder_manager = new Dictionary<IntPtr, ClientProtocol>();

        #region member datas
        private IntPtr _native_protocol;
        public OnWriteDataFunction OnWriteData = null;
        public OnReceiveMessageFunction OnReceiveMessage = null;
        public OnInitNewSessionFunction OnInitNewSession = null;
        public OnInitReconnectSessionFunction OnInitReconnectSession = null;
        public OnCloseFunction OnClose = null;
        public OnHandshakeDoneFunction OnHandshakeDone = null;
        public OnHandshakeDoneFunction OnHandshakeUpdate = null;
        public OnErrorFunction OnError = null;
        #endregion
        protected IntPtr NativeProtocol {
            get {
                if (null == _native_protocol) {
                    _native_protocol = libatgw_inner_v1_c_create();
                    {
                        // write
                        IntPtr fn = Marshal.GetFunctionPointerForDelegate(new libatgw_inner_v1_c_on_write_start_fn_t(proto_on_write_start_fn));
                        libatgw_inner_v1_c_gset_on_write_start_fn(fn);

                        // message
                        fn = Marshal.GetFunctionPointerForDelegate(new libatgw_inner_v1_c_on_message_fn_t(proto_on_message_fn));
                        libatgw_inner_v1_c_gset_on_message_fn(fn);

                        // new session
                        fn = Marshal.GetFunctionPointerForDelegate(new libatgw_inner_v1_c_on_init_new_session_fn_t(proto_on_init_new_session_fn));
                        libatgw_inner_v1_c_gset_on_init_new_session_fn(fn);

                        // reconnect session
                        fn = Marshal.GetFunctionPointerForDelegate(new libatgw_inner_v1_c_on_init_reconnect_fn_t(proto_on_init_reconnect_fn));
                        libatgw_inner_v1_c_gset_on_init_reconnect_fn(fn);

                        // on close
                        fn = Marshal.GetFunctionPointerForDelegate(new libatgw_inner_v1_c_on_close_fn_t(proto_on_close_fn));
                        libatgw_inner_v1_c_gset_on_close_fn(fn);

                        // on handshake done
                        fn = Marshal.GetFunctionPointerForDelegate(new libatgw_inner_v1_c_on_handshake_done_fn_t(proto_on_handshake_done_fn));
                        libatgw_inner_v1_c_gset_on_handshake_done_fn(fn);

                        // on handshake update finished
                        fn = Marshal.GetFunctionPointerForDelegate(new libatgw_inner_v1_c_on_handshake_done_fn_t(proto_on_handshake_update_fn));
                        libatgw_inner_v1_c_gset_on_handshake_update_fn(fn);

                        // on error
                        fn = Marshal.GetFunctionPointerForDelegate(new libatgw_inner_v1_c_on_error_fn_t(proto_on_error_fn));
                        libatgw_inner_v1_c_gset_on_error_fn(fn);
                    }

                    return _native_protocol;
                }

                return _native_protocol;
            }
        }

        public ClientProtocol() {
            if (null == NativeProtocol) {
                throw new System.OutOfMemoryException("Can not create native atgateway inner protocol v1 object");
            } else {
                _binder_manager.Add(NativeProtocol, this);
            }
        }

        ~ClientProtocol() {
            if (null != _native_protocol) {
                libatgw_inner_v1_c_destroy(_native_protocol);
                _binder_manager.Remove(_native_protocol);
            }
        }

        #region delegate setter
        /// <summary>
        /// Set libatgw_inner_v1_c_on_write_start_fn_t of global callback set.
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_write_start_fn_t</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_write_start_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_message_fn_t of global callback set.
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_message_fn_t</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_message_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_init_new_session_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_init_new_session_fn_t</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_init_new_session_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_init_reconnect_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_init_reconnect_fn_t</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_init_reconnect_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_close_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_close_fn_t</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_close_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_handshake_done_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_handshake_done_fn_t</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_handshake_done_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_handshake_done_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_handshake_done_fn_t</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_gset_on_handshake_update_fn(IntPtr fn);

        /// <summary>
        /// Set libatgw_inner_v1_c_on_error_fn_t function of global callback set
        /// </summary>
        /// <param name="fn">delegate function of type libatgw_inner_v1_c_on_error_fn_t</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
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

        static public Int32 proto_on_write_start_fn(IntPtr context, IntPtr buffer, UInt64 buffer_length, [Out] Int32 is_done) {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self) {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnWriteData) {
                byte[] data_buffer = new byte[buffer_length];
                Marshal.Copy(buffer, data_buffer, 0, (int)buffer_length);
                bool is_done_b = false;
                Int32 ret = self.OnWriteData(self, data_buffer, is_done_b);
                is_done = is_done_b ? 1 : 0;
                return ret;
            }

            is_done = 1;
            return (Int32)error_code_t.EN_ECT_MISS_CALLBACKS;
        }

        static public Int32 proto_on_message_fn(IntPtr context, IntPtr buffer, UInt64 buffer_length)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnReceiveMessage)
            {
                byte[] data_buffer = new byte[buffer_length];
                Marshal.Copy(buffer, data_buffer, 0, (int)buffer_length);
                return self.OnReceiveMessage(self, data_buffer);
            }

            return 0;
        }

        static public Int32 proto_on_init_new_session_fn(IntPtr context, [Out] UInt64 session_id)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnInitNewSession)
            {
                return self.OnInitNewSession(self, session_id);
            }

            return (Int32)error_code_t.EN_ECT_MISS_CALLBACKS;
        }

        static public Int32 proto_on_init_reconnect_fn(IntPtr context, UInt64 session_id)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnInitReconnectSession)
            {
                return self.OnInitReconnectSession(self, session_id);
            }

            return (Int32)error_code_t.EN_ECT_MISS_CALLBACKS;
        }

        static public Int32 proto_on_close_fn(IntPtr context, Int32 reason)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnClose)
            {
                return self.OnClose(self, reason);
            }

            return 0;
        }

        static public Int32 proto_on_handshake_done_fn(IntPtr context, Int32 status)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnHandshakeDone)
            {
                return self.OnHandshakeDone(self, status);
            }

            return 0;
        }

        static public Int32 proto_on_handshake_update_fn(IntPtr context, Int32 status)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null != self.OnHandshakeUpdate)
            {
                return self.OnHandshakeUpdate(self, status);
            }

            return 0;
        }

        static public Int32 proto_on_error_fn(IntPtr context, IntPtr file_name, Int32 line, Int32 error_code, IntPtr message)
        {
            ClientProtocol self = GetClientProtocol(context);
            if (null == self)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
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
        [DllImport("libatgw_inner_v1_c", CallingConvention=CallingConvention.Cdecl)]
        private static extern IntPtr libatgw_inner_v1_c_create();

        /// <summary>
        /// Destroy a inner protocol context for atgateway
        /// </summary>
        /// <param name="ptr">protocol context for atgateway</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_destroy(IntPtr ptr);

        /// <summary>
        /// Set receive buffer limit in the protocol handle
        /// </summary>
        /// <param name="context"></param>
        /// <param name="max_size">max size</param>
        /// <param name="max_number">max message number</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_set_recv_buffer_limit(IntPtr context, UInt64 max_size, UInt64 max_number);

        /// <summary>
        /// Set send buffer limit in the protocol handle
        /// </summary>
        /// <param name="context"></param>
        /// <param name="max_size">max size</param>
        /// <param name="max_number">max message number</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_set_send_buffer_limit(IntPtr context, UInt64 max_size, UInt64 max_number);

        /// <summary>
        /// Start a session
        /// </summary>
        /// <param name="context"></param>
        /// <returns>0 or error code</returns>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_start_session(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_reconnect_session(IntPtr context, UInt64 sessios_id, Int32 crypt_type,
                                                                           byte[] secret_buf, UInt64 secret_len, UInt32 keybits);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_get_info(IntPtr context, StringBuilder info_str, UInt64 info_len);

        /// <summary>
        /// Set private data of specify protocol context
        /// </summary>
        /// <param name="context">protocol context</param>
        /// <param name="data">private data</param>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_set_private_data(IntPtr context, IntPtr data);

        /// <summary>
        /// Get private data of specify protocol context
        /// </summary>
        /// <param name="context"></param>
        /// <returns>private data</returns>
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr libatgw_inner_v1_c_get_private_data(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern UInt64 libatgw_inner_v1_c_get_session_id(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_get_crypt_type(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern UInt64 libatgw_inner_v1_c_get_crypt_secret_size(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern UInt64 libatgw_inner_v1_c_copy_crypt_secret(IntPtr context, byte[] secret, UInt64 available_size);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern UInt32 libatgw_inner_v1_c_get_crypt_keybits(IntPtr context);
                           
        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private unsafe static extern void libatgw_inner_v1_c_read_alloc(IntPtr context, UInt64 suggested_size, [Out] byte* out_buf,
                                                                 [Out] UInt64 out_len);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern void libatgw_inner_v1_c_read(IntPtr context, Int32 ssz, byte[] buff, UInt64 len, [Out] Int32 errcode);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_write_done(IntPtr context, Int32 status);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_post_msg(IntPtr context, byte[] out_buf, UInt64 out_len);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_send_ping(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int64 libatgw_inner_v1_c_get_ping_delta(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_close(IntPtr context, Int32 reason);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_is_closing(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_is_closed(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_is_handshake_updating(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_is_handshake_done(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_is_writing(IntPtr context);

        [DllImport("libatgw_inner_v1_c", CallingConvention = CallingConvention.Cdecl)]
        private static extern Int32 libatgw_inner_v1_c_is_in_callback(IntPtr context);

        #endregion

        /// <summary>
        /// Get imformation of protocol handle, it cost a lot and should not be called frequently.
        /// </summary>
        public String Information {
            get {
                IntPtr native = NativeProtocol;
                if (null == native) {
                    return "";
                }

                StringBuilder sb = new StringBuilder(4096);
                libatgw_inner_v1_c_get_info(native, sb, (UInt64)sb.Capacity);
                return sb.ToString();
            }
        }

        public void SetReceiveBufferLimit(UInt64 max_size, UInt64 max_number) {
            IntPtr native = NativeProtocol;
            if (null == native)
            {
                return;
            }

            libatgw_inner_v1_c_set_recv_buffer_limit(native, max_size, max_number);
        }

        public void SetSendBufferLimit(UInt64 max_size, UInt64 max_number)
        {
            IntPtr native = NativeProtocol;
            if (null == native)
            {
                return;
            }

            libatgw_inner_v1_c_set_send_buffer_limit(native, max_size, max_number);
        }

        public Int32 StartSession()
        {
            IntPtr native = NativeProtocol;
            if (null == native)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            return libatgw_inner_v1_c_start_session(native);
        }

        public Int32 ReconnectSession(UInt64 session_id, Int32 crypt_type, byte[] secret, UInt32 keybits)
        {
            IntPtr native = NativeProtocol;
            if (null == native)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            return libatgw_inner_v1_c_reconnect_session(native, session_id, crypt_type, secret, (UInt64)secret.Length, keybits);
        }

        public UInt64 SessionID {
            get
            {
                IntPtr native = NativeProtocol;
                if (null == native)
                {
                    return 0;
                }

                return libatgw_inner_v1_c_get_session_id(native);
            }
        }

        public Int32 CryptType
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (null == native)
                {
                    return 0;
                }

                return libatgw_inner_v1_c_get_crypt_type(native);
            }
        }

        public byte[] Secret
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (null == native)
                {
                    return new byte[0];
                }

                UInt64 secret_len = libatgw_inner_v1_c_get_crypt_secret_size(native);
                byte[] ret = new byte[secret_len];
                libatgw_inner_v1_c_copy_crypt_secret(native, ret, secret_len);
                return ret;
            }
        }

        public UInt32 Keybits
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (null == native)
                {
                    return 0;
                }

                return libatgw_inner_v1_c_get_crypt_keybits(native);
            }
        }

        public unsafe  void OnReadAlloc(UInt64 suggest_size, [Out] byte* out_buf, [Out] UInt64 len) {
            IntPtr native = NativeProtocol;
            if (null == native)
            {
                return;
            }

            libatgw_inner_v1_c_read_alloc(native, suggest_size, out_buf, len);
        }

        /// <summary>
        /// Call it when receive any data from peer
        /// </summary>
        /// <param name="ssz">read data length or error code</param>
        /// <param name="buf">available buffer block</param>
        /// <returns>0 or error code</returns>
        public Int32 OnRead(Int32 ssz, byte[] buf)
        {
            IntPtr native = NativeProtocol;
            if (null == native)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null == buf || 0 == buf.Length) {
                return 0;
            }

            Int32 ret = 0;
            libatgw_inner_v1_c_read(native, ssz, buf, (UInt64)buf.Length, ret);
            return ret;
        }

        /// <summary>
        /// If OnWriteData set is_done to false, this function should be called when the writing is finished.
        /// </summary>
        /// <param name="status">0 or error code</param>
        /// <returns></returns>
        public Int32 NotifyWriteDone(Int32 status) {
            IntPtr native = NativeProtocol;
            if (null == native)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            return libatgw_inner_v1_c_write_done(native, status);
        }

        public Int32 PostMessage(byte[] buf) {
            IntPtr native = NativeProtocol;
            if (null == native)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            if (null == buf || 0 == buf.Length)
            {
                return 0;
            }

            return libatgw_inner_v1_c_post_msg(native, buf, (UInt64)buf.Length);
        }

        public Int32 SendPing()
        {
            IntPtr native = NativeProtocol;
            if (null == native)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            return libatgw_inner_v1_c_send_ping(native);
        }

        public Int64 LastPingDelta
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (null == native)
                {
                    return 0;
                }

                return libatgw_inner_v1_c_get_ping_delta(native);
            }
        }

        public Int32 Close(Int32 reason = (Int32)close_reason_t.EN_CRT_UNKNOWN)
        {
            IntPtr native = NativeProtocol;
            if (null == native)
            {
                return (Int32)error_code_t.EN_ECT_HANDLE_NOT_FOUND;
            }

            return libatgw_inner_v1_c_close(native, reason);
        }

        public bool IsClosing
        {
            get
            {
                IntPtr native = NativeProtocol;
                if (null == native)
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
                if (null == native)
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
                if (null == native)
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
                if (null == native)
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
                if (null == native)
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
                if (null == native)
                {
                    return false;
                }

                return 0 != libatgw_inner_v1_c_is_in_callback(native);
            }
        }
    }
}
