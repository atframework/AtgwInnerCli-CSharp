using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;

using atframe.gw.inner;
using System.Collections;

namespace AtgwInnerCliHelloTest
{
    class Program
    {
        private static bool exit = false;
        private static ClientProtocol CreateClient(TcpClient sock)
        {
            ClientProtocol proto = new ClientProtocol();

            proto.OnWriteData = (ClientProtocol self, byte[] data, ref bool is_done) =>
            {
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

            proto.OnReceiveMessage = (ClientProtocol self, byte[] data) =>
            {
                Console.WriteLine(String.Format("[Info]: session 0x{0:X0000000000000000} recv {1}", proto.SessionID,
                    System.Text.Encoding.UTF8.GetString(data)));
                return 0;
            };

            proto.OnClose = (ClientProtocol self, Int32 reason) =>
            {
                Console.WriteLine(String.Format("[Notice]: client closed, reason: {0}", reason));
                exit = (Int32)ClientProtocol.close_reason_t.EN_CRT_RECONNECT_BOUND <= reason;
                sock.Close();
                return 0;
            };

            proto.OnHandshakeDone = (ClientProtocol self, Int32 status) =>
            {
                Console.WriteLine(String.Format("[Info]: handshake done, status {0}\n{1}", status,
                    self.Information
                ));
                exit = status < 0;
                return 0;
            };

            proto.OnHandshakeUpdate = (ClientProtocol self, Int32 status) =>
            {
                Console.WriteLine(String.Format("[Info]: handshake updated, status {0}\n{1}", status,
                    self.Information
                ));
                exit = status < 0;
                return 0;
            };

            proto.OnError = (ClientProtocol self, String file_name, Int32 line, Int32 error_code, String message) =>
            {
                Console.WriteLine(String.Format("[Error]: {0}:{1} error code: {2}, message: {3}", file_name, line, error_code, message));
                return 0;
            };

            return proto;
        }

        static unsafe void Main(string[] args)
        {
            if (args.Length < 2)
            {
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
            if (ret < 0)
            {
                Console.WriteLine(String.Format("[Error]: Start session failed, res: {0}", ret));
                return;
            }

            UInt64 seq = 0;
            while (true)
            {
                if (exit)
                {
                    break;
                }

                if (null == sock || null == sock.Client || !sock.Connected)
                {
                    try
                    {
                        byte[] secret = proto.Secret;
                        UInt64 session_id = proto.SessionID;
                        UInt32 keybits = proto.Keybits;
                        Int32 crypt_type = proto.CryptType;

                        sock = new TcpClient();
                        proto = CreateClient(sock);
                        sock.Client.Connect(args[0], int.Parse(args[1]));

                        if (session_id > 0)
                        {
                            proto.ReconnectSession(session_id, crypt_type, secret, keybits);
                        }
                        else
                        {
                            proto.StartSession();
                        }
                    }
                    catch (Exception e)
                    {
                        sock.Close();
                        sock = null;
                        Console.WriteLine(e.ToString());
                        return;
                    }
                }

                bool is_send = false;
                // We use sync call for simple, in the real world, you should use socket event to receive and send data.
                try
                {
                    byte[] buffer = new byte[8192]; // 8KB
                    sock.ReceiveTimeout = 2000;
                    int nread = sock.Client.Receive(buffer);
                    if (nread > 0)
                    {
                        Int32 res = proto.ReadFrom(buffer, (UInt64)nread);
                        if (res < 0) {
                            sock.Close();
                            sock = null;
                            Console.WriteLine(String.Format("[Error]: read socket data error, ret: {0}", res));
                        }
                    }
                }
                catch (SocketException e)
                {
                    if (e.SocketErrorCode == SocketError.TimedOut)
                    {
                        is_send = true;
                    }
                    else
                    {
                        sock.Close();
                        sock = null;
                        Console.WriteLine(e.ToString());
                    }
                }
                catch (Exception e)
                {
                    sock.Close();
                    sock = null;
                    Console.WriteLine(e.ToString());
                }

                if (is_send && proto.IsHandshakeDone && !proto.IsClosing)
                {
                    String send_data = String.Format("session 0x{0:X0000000000000000} send index: {1}", proto.SessionID, ++seq);
                    proto.PostMessage(System.Text.Encoding.UTF8.GetBytes(send_data));
                    Console.WriteLine(String.Format("[Info]: send {0}", send_data));
                }
            }
        }
    }
}
