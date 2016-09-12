using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;

using atframe.gw.inner;

namespace AtgwInnerCliHelloTest
{
    class Program
    {
        private static bool exit = false;
        private static ClientProtocol CreateClient(TcpClient sock) {
            ClientProtocol proto = new ClientProtocol();

            proto.OnWriteData = (ClientProtocol self, byte[] data, ref bool is_done) => {
                try
                {
                    sock.Client.Send(data);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                    sock.Client.Close();
                    sock = null;
                }
                is_done = true;
                return 0;
            };

            proto.OnReceiveMessage = (ClientProtocol self, byte[] data) => {
                Console.WriteLine(String.Format("[Info]: recv {0}", data.ToString()));
                return 0;
            };

            proto.OnClose = (ClientProtocol self, Int32 reason) => {
                Console.WriteLine(String.Format("[Notice]: client closed, reason: {0}", reason));
                exit = (Int32)ClientProtocol.close_reason_t.EN_CRT_RECONNECT_BOUND <= reason;
                return 0;
            };

            proto.OnHandshakeDone = (ClientProtocol self, Int32 status) => {
                Console.WriteLine(String.Format("[Info]: handshake done, status {0}\n{1}", status,
                    self.Information
                ));
                exit = status < 0;
                return 0;
            };

            proto.OnHandshakeUpdate = (ClientProtocol self, Int32 status) => {
                Console.WriteLine(String.Format("[Info]: handshake updated, status {0}\n{1}", status,
                    self.Information
                ));
                exit = status < 0;
                return 0;
            };

            proto.OnError = (ClientProtocol self, String file_name, Int32 line, Int32 error_code, String message) => {
                Console.WriteLine(String.Format("[Error]: {0}:{1} error code: {2}, message: {3}", file_name, line, error_code, message));
                return 0;
            };

            return proto;
        }

        static unsafe void Main(string[] args)
        {
            if (args.Length < 2) {
                Console.WriteLine(String.Format("usage: {0} <ip> <port>", System.Environment.CommandLine));
                return;
            }

            
            TcpClient sock = new TcpClient();

            ClientProtocol proto = CreateClient(sock);
            try
            {
                sock.Client.Connect(args[0], int.Parse(args[1]));
                Console.WriteLine(String.Format("[Info]: Connect for first time success"));
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                return;
            }

            int ret = proto.StartSession();
            if (ret < 0) {
                Console.WriteLine(String.Format("[Error]: Start session failed, res: {0}", ret));
                return;
            }

            UInt64 seq = 0;
            while (true) {
                if (exit) {
                    break;
                }

                if (null == sock) {
                    try
                    {
                        byte[] secret = proto.Secret;
                        UInt64 session_id = proto.SessionID;
                        UInt32 keybits = proto.Keybits;
                        Int32 crypt_type = proto.CryptType;

                        sock = new TcpClient();
                        proto = CreateClient(sock);
                        proto.ReconnectSession(session_id, crypt_type, secret, keybits);
                    }
                    catch (Exception e) {
                        sock.Close();
                        sock = null;
                        Console.WriteLine(e.ToString());
                        return;
                    }
                }

                bool is_send = false;
                try
                {
                    byte[] buffer = new byte[8192]; // 8KB
                    sock.ReceiveTimeout = 2000;
                    int nread = sock.Client.Receive(buffer);
                    int noffset = 0;
                    while (nread > noffset)
                    {
                        byte* out_buf = null;
                        UInt64 out_len = 0;
                        proto.OnReadAlloc((UInt64)(nread - noffset), ref out_buf, ref out_len);

                        // free buffer memory is enough to store all received data
                        if (out_len >= (UInt64)(nread - noffset)) {
                            proto.OnRead(out_buf, (UInt64)(nread - noffset));
                            noffset = nread;
                        }
                        else // free buffer memory is not enough to store all received data
                        {
                            proto.OnRead(out_buf, out_len);
                            noffset += (int)out_len;
                        }
                    }
                }
                catch (SocketException e) {
                    // better if judge if it's timeout exception
                    is_send = true;
                }
                catch (Exception e)
                {
                    sock.Close();
                    sock = null;
                    Console.WriteLine(e.ToString());
                }

                if (is_send)
                {
                    String send_data = String.Format("[Info]: session {0} send index: {1}", proto.SessionID, seq);
                    proto.PostMessage(System.Text.Encoding.UTF8.GetBytes(send_data));
                    Console.WriteLine(String.Format("[Info]: send {0}", send_data));
                }
            }
        }
    }
}
