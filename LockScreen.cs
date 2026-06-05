// =============================================================================
//  StillGuard（靜守）— 鍵鼠鎖定工具
//  依 DESIGN.md v1.0 實作。C# + WinForms，目標 .NET Framework 4.x。
//  以 Windows 內建 csc.exe 編譯為單一 exe（見 build.bat）。
//
//  安全邊界：本工具屬使用者層級，「防隨手亂動」而非「防內行破解」。
//  Ctrl+Alt+Del 仍可進入安全桌面結束本程式——此為無核心驅動之先天限制。
// =============================================================================

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;   // System.Web.Extensions.dll
using System.Windows.Forms;

namespace StillGuard
{
    // =========================================================================
    //  密碼策略（第 7 節，公開友善版）
    //  - 原始碼「不含任何機密」：無預設主密碼、無寫死緊急碼。
    //  - 主密碼：必設。首次於設定介面建立，以 PBKDF2 雜湊存入各機自己的 config.json。
    //  - 救援碼：使用者自選是否設定，同樣以雜湊存入 config.json。
    //  - 主密碼或救援碼（若有設）皆可解鎖。機密只存在各機本地，雲端原始碼一概沒有。
    // =========================================================================

    // 設定檔中的密碼欄位（僅存雜湊與鹽，不存明碼）。
    internal sealed class PasswordConfig
    {
        public string hash;        // base64(PBKDF2)
        public string salt;        // base64
        public int iterations = 100000;
    }

    // PBKDF2 密碼雜湊與驗證。
    internal static class PasswordManager
    {
        // 是否已設定主密碼（未設定則不允許鎖定，避免把自己鎖死）。
        public static bool HasMaster(AppConfig cfg)
        {
            return cfg != null && cfg.password != null
                && !string.IsNullOrEmpty(cfg.password.hash) && !string.IsNullOrEmpty(cfg.password.salt);
        }

        public static void SetPassword(AppConfig cfg, string newPassword)
        {
            cfg.password = Make(newPassword);
        }

        // 設定 / 清除救援碼（傳空字串視為清除）。
        public static void SetRescue(AppConfig cfg, string rescuePassword)
        {
            cfg.rescue = string.IsNullOrEmpty(rescuePassword) ? null : Make(rescuePassword);
        }

        public static bool HasRescue(AppConfig cfg)
        {
            return cfg != null && cfg.rescue != null
                && !string.IsNullOrEmpty(cfg.rescue.hash) && !string.IsNullOrEmpty(cfg.rescue.salt);
        }

        // 主密碼或救援碼任一相符即通過。無內建後門。
        public static bool Verify(AppConfig cfg, string input)
        {
            if (input == null || cfg == null) return false;
            if (VerifyAgainst(cfg.password, input)) return true;
            if (VerifyAgainst(cfg.rescue, input)) return true;
            return false;
        }

        private static bool VerifyAgainst(PasswordConfig pc, string input)
        {
            if (pc == null || string.IsNullOrEmpty(pc.hash) || string.IsNullOrEmpty(pc.salt)) return false;
            try
            {
                byte[] salt = Convert.FromBase64String(pc.salt);
                byte[] expected = Convert.FromBase64String(pc.hash);
                byte[] actual = Derive(input, salt, pc.iterations <= 0 ? 100000 : pc.iterations);
                return FixedTimeEquals(expected, actual);
            }
            catch { return false; }
        }

        private static PasswordConfig Make(string password)
        {
            byte[] salt = new byte[16];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(salt);
            int iter = 100000;
            byte[] hash = Derive(password, salt, iter);
            return new PasswordConfig
            {
                salt = Convert.ToBase64String(salt),
                hash = Convert.ToBase64String(hash),
                iterations = iter
            };
        }

        private static byte[] Derive(string password, byte[] salt, int iterations)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password ?? "", salt, iterations))
                return pbkdf2.GetBytes(32);
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }

    // =========================================================================
    //  OTP 一次性救援碼設定（送至手機 / APP）
    // =========================================================================
    internal sealed class OtpConfig
    {
        public bool enabled = false;
        public string channel = "telegram";        // telegram | discord | ntfy
        public string telegramToken = "";          // 機密，DPAPI 加密存放
        public string telegramChatId = "";
        public string discordWebhook = "";         // 機密，DPAPI 加密存放
        public string ntfyServer = "https://ntfy.sh";
        public string ntfyTopic = "";
    }

    // 以 Windows DPAPI（當前使用者）加密 / 解密機密字串；存放格式加前綴 "enc:"。
    internal static class DataProtector
    {
        public static string Protect(string plain)
        {
            if (string.IsNullOrEmpty(plain)) return "";
            if (plain.StartsWith("enc:")) return plain;   // 已是加密字串
            try
            {
                byte[] enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(plain), null, DataProtectionScope.CurrentUser);
                return "enc:" + Convert.ToBase64String(enc);
            }
            catch { return plain; }
        }

        public static string Unprotect(string stored)
        {
            if (string.IsNullOrEmpty(stored)) return "";
            if (!stored.StartsWith("enc:")) return stored;  // 相容明碼
            try
            {
                byte[] enc = Convert.FromBase64String(stored.Substring(4));
                byte[] data = ProtectedData.Unprotect(enc, null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(data);
            }
            catch { return ""; }
        }
    }

    // =========================================================================
    //  通知通道（策略 + 工廠）—— 新增通道 = 新增一個 INotifier + 於工廠註冊
    // =========================================================================
    internal interface INotifier
    {
        bool Send(string message, out string error);
    }

    internal sealed class TelegramNotifier : INotifier
    {
        private readonly string _token, _chatId;
        public TelegramNotifier(string token, string chatId) { _token = token; _chatId = chatId; }
        public bool Send(string message, out string error)
        {
            error = null;
            if (string.IsNullOrEmpty(_token) || string.IsNullOrEmpty(_chatId)) { error = "Telegram token / chatId 未設定"; return false; }
            try
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
                using (var wc = new WebClient())
                {
                    var data = new System.Collections.Specialized.NameValueCollection();
                    data["chat_id"] = _chatId;
                    data["text"] = message;
                    wc.UploadValues("https://api.telegram.org/bot" + _token + "/sendMessage", data);
                }
                return true;
            }
            catch (Exception ex) { error = ex.Message; return false; }
        }
    }

    internal sealed class DiscordNotifier : INotifier
    {
        private readonly string _webhook;
        public DiscordNotifier(string webhook) { _webhook = webhook; }
        public bool Send(string message, out string error)
        {
            error = null;
            if (string.IsNullOrEmpty(_webhook)) { error = "Discord webhook 未設定"; return false; }
            try
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
                using (var wc = new WebClient())
                {
                    wc.Headers[HttpRequestHeader.ContentType] = "application/json";
                    string json = "{\"content\":\"" + JsonEscape(message) + "\"}";
                    wc.UploadString(_webhook, "POST", json);
                }
                return true;
            }
            catch (Exception ex) { error = ex.Message; return false; }
        }
        private static string JsonEscape(string s)
        {
            return (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "");
        }
    }

    internal sealed class NtfyNotifier : INotifier
    {
        private readonly string _server, _topic;
        public NtfyNotifier(string server, string topic) { _server = server; _topic = topic; }
        public bool Send(string message, out string error)
        {
            error = null;
            if (string.IsNullOrEmpty(_topic)) { error = "ntfy 主題未設定"; return false; }
            try
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
                string baseUrl = string.IsNullOrEmpty(_server) ? "https://ntfy.sh" : _server.TrimEnd('/');
                using (var wc = new WebClient())
                {
                    wc.Encoding = Encoding.UTF8;
                    wc.UploadString(baseUrl + "/" + _topic, "POST", message);
                }
                return true;
            }
            catch (Exception ex) { error = ex.Message; return false; }
        }
    }

    internal static class NotifierFactory
    {
        // 依設定建立通道（機密欄位於此解密）
        public static INotifier Create(OtpConfig cfg)
        {
            if (cfg == null) return null;
            switch ((cfg.channel ?? "").ToLowerInvariant())
            {
                case "telegram": return new TelegramNotifier(DataProtector.Unprotect(cfg.telegramToken), cfg.telegramChatId);
                case "discord": return new DiscordNotifier(DataProtector.Unprotect(cfg.discordWebhook));
                case "ntfy": return new NtfyNotifier(cfg.ntfyServer, cfg.ntfyTopic);
                default: return null;
            }
        }

        public static bool IsConfigured(OtpConfig cfg)
        {
            if (cfg == null || !cfg.enabled) return false;
            switch ((cfg.channel ?? "").ToLowerInvariant())
            {
                case "telegram": return !string.IsNullOrEmpty(cfg.telegramToken) && !string.IsNullOrEmpty(cfg.telegramChatId);
                case "discord": return !string.IsNullOrEmpty(cfg.discordWebhook);
                case "ntfy": return !string.IsNullOrEmpty(cfg.ntfyTopic);
                default: return false;
            }
        }
    }

    // OTP 產生與驗證（一次性、限時）
    internal sealed class OtpState
    {
        private readonly object _lock = new object();   // Generate（UI 緒）與 Verify（輪詢緒）可能並行
        private string _code;
        private DateTime _expiry = DateTime.MinValue;
        private bool _used;

        public int ValiditySeconds = 300;   // 5 分鐘

        public string Generate()
        {
            byte[] b = new byte[4];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(b);
            uint v = (uint)(BitConverter.ToUInt32(b, 0) % 1000000);
            lock (_lock)
            {
                _code = v.ToString("D6");
                _expiry = DateTime.Now.AddSeconds(ValiditySeconds);
                _used = false;
                return _code;
            }
        }

        public bool Verify(string input)
        {
            lock (_lock)
            {
                if (string.IsNullOrEmpty(_code) || _used) return false;
                if (DateTime.Now > _expiry) return false;
                if (input != _code) return false;
                _used = true;   // 一次性
                return true;
            }
        }
    }

    // =========================================================================
    //  設定模型（config.json）
    // =========================================================================
    internal sealed class BackgroundConfig
    {
        public string type = "blurDesktop";   // blurDesktop | image | solidDark
        public int blur = 18;                  // 模糊強度
        public double dim = 0.25;              // 變暗程度 0~1
        public string path = null;             // type=image 時的圖片路徑
    }

    internal sealed class WidgetConfig
    {
        public string type;                    // clock | date | text | hint | weather
        public string format;
        public string content;
        public string city;
        public string y = "50%";               // 垂直位置（百分比或像素）
        public int fontSize = 20;
        public bool enabled = true;
    }

    internal sealed class AppConfig
    {
        public BackgroundConfig background = new BackgroundConfig();
        public int idleTimeoutSec = 10;
        public string hotkey = "Ctrl+Alt+L";      // 全域鎖定快捷鍵
        public bool showClock = true;             // 鎖屏是否顯示內建時鐘
        public bool showTerminal = false;         // 鎖屏是否顯示終端特效（純裝飾）
        public string terminalStyle = "hacker";   // 終端風格：hacker（駭客）| guard（仿真守護）
        public bool fakeUpdate = false;            // 偽 Windows 更新畫面（障眼模式，蓋過其他顯示）
        public string fakeUpdateLang = "zh";       // 偽更新畫面文字語言：zh（中文）| en（英文）
        public List<WidgetConfig> widgets = new List<WidgetConfig>();
        public PasswordConfig password = null;   // 主密碼雜湊（由 UI 設定）
        public PasswordConfig rescue = null;     // 救援碼雜湊（可選，由 UI 設定）
        public OtpConfig otp = new OtpConfig();   // OTP 一次性救援碼通道

        public static AppConfig LoadOrDefault(string path)
        {
            try
            {
                if (!File.Exists(path)) return Default();
                string json = File.ReadAllText(path, Encoding.UTF8);
                var ser = new JavaScriptSerializer();
                var root = ser.Deserialize<Dictionary<string, object>>(json);
                return FromDict(root);
            }
            catch
            {
                // 設定壞了不應使程式無法鎖定——退回安全預設。
                return Default();
            }
        }

        private static AppConfig FromDict(Dictionary<string, object> root)
        {
            var cfg = new AppConfig();

            if (root.ContainsKey("background") && root["background"] is Dictionary<string, object>)
            {
                var b = (Dictionary<string, object>)root["background"];
                cfg.background.type = GetStr(b, "type", cfg.background.type);
                cfg.background.blur = GetInt(b, "blur", cfg.background.blur);
                cfg.background.dim = GetDouble(b, "dim", cfg.background.dim);
                cfg.background.path = GetStr(b, "path", null);
            }

            cfg.idleTimeoutSec = GetInt(root, "idleTimeoutSec", cfg.idleTimeoutSec);
            cfg.hotkey = GetStr(root, "hotkey", cfg.hotkey);
            cfg.showClock = GetBool(root, "showClock", cfg.showClock);
            cfg.showTerminal = GetBool(root, "showTerminal", cfg.showTerminal);
            cfg.terminalStyle = GetStr(root, "terminalStyle", cfg.terminalStyle);
            cfg.fakeUpdate = GetBool(root, "fakeUpdate", cfg.fakeUpdate);
            cfg.fakeUpdateLang = GetStr(root, "fakeUpdateLang", cfg.fakeUpdateLang);

            cfg.password = ReadPwd(root, "password");
            cfg.rescue = ReadPwd(root, "rescue");

            if (root.ContainsKey("otp") && root["otp"] is Dictionary<string, object>)
            {
                var o = (Dictionary<string, object>)root["otp"];
                cfg.otp = new OtpConfig
                {
                    enabled = GetBool(o, "enabled", false),
                    channel = GetStr(o, "channel", "telegram"),
                    telegramToken = GetStr(o, "telegramToken", ""),
                    telegramChatId = GetStr(o, "telegramChatId", ""),
                    discordWebhook = GetStr(o, "discordWebhook", ""),
                    ntfyServer = GetStr(o, "ntfyServer", "https://ntfy.sh"),
                    ntfyTopic = GetStr(o, "ntfyTopic", "")
                };
            }

            cfg.widgets.Clear();
            if (root.ContainsKey("widgets") && root["widgets"] is System.Collections.IEnumerable)
            {
                foreach (var item in (System.Collections.IEnumerable)root["widgets"])
                {
                    var w = item as Dictionary<string, object>;
                    if (w == null) continue;
                    var wc = new WidgetConfig();
                    wc.type = GetStr(w, "type", null);
                    wc.format = GetStr(w, "format", null);
                    wc.content = GetStr(w, "content", null);
                    wc.city = GetStr(w, "city", null);
                    wc.y = GetStr(w, "y", "50%");
                    wc.fontSize = GetInt(w, "fontSize", 20);
                    wc.enabled = GetBool(w, "enabled", true);
                    if (!string.IsNullOrEmpty(wc.type)) cfg.widgets.Add(wc);
                }
            }
            return cfg;
        }

        public static AppConfig Default()
        {
            // 預設：顯示內建時鐘即可（不再使用自訂 widget 清單）。
            return new AppConfig();
        }

        // 手寫輸出整齊 JSON，並保留密碼雜湊區塊。
        public void Save(string path)
        {
            var sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine("  \"background\": { \"type\": " + JStr(background.type) +
                          ", \"blur\": " + background.blur +
                          ", \"dim\": " + background.dim.ToString(CultureInfo.InvariantCulture) +
                          (string.IsNullOrEmpty(background.path) ? "" : ", \"path\": " + JStr(background.path)) +
                          " },");
            sb.AppendLine("  \"idleTimeoutSec\": " + idleTimeoutSec + ",");
            sb.AppendLine("  \"hotkey\": " + JStr(hotkey) + ",");
            // showClock 之後的成員（password / rescue / otp），統一處理逗號
            var members = new List<string>();
            if (password != null && !string.IsNullOrEmpty(password.hash)) members.Add(PwdJson("password", password));
            if (rescue != null && !string.IsNullOrEmpty(rescue.hash)) members.Add(PwdJson("rescue", rescue));
            if (otp != null) members.Add(OtpJson(otp));

            sb.AppendLine("  \"showClock\": " + (showClock ? "true" : "false") + ",");
            sb.AppendLine("  \"showTerminal\": " + (showTerminal ? "true" : "false") + ",");
            sb.AppendLine("  \"terminalStyle\": " + JStr(terminalStyle) + ",");
            sb.AppendLine("  \"fakeUpdate\": " + (fakeUpdate ? "true" : "false") + ",");
            sb.AppendLine("  \"fakeUpdateLang\": " + JStr(fakeUpdateLang) + (members.Count > 0 ? "," : ""));
            for (int i = 0; i < members.Count; i++)
                sb.AppendLine("  " + members[i] + (i < members.Count - 1 ? "," : ""));

            sb.AppendLine("}");

            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
        }

        private static string PwdJson(string key, PasswordConfig pc)
        {
            return "\"" + key + "\": { \"hash\": " + JStr(pc.hash) +
                   ", \"salt\": " + JStr(pc.salt) +
                   ", \"iterations\": " + pc.iterations + " }";
        }

        private static string OtpJson(OtpConfig o)
        {
            return "\"otp\": { \"enabled\": " + (o.enabled ? "true" : "false") +
                   ", \"channel\": " + JStr(o.channel) +
                   ", \"telegramToken\": " + JStr(o.telegramToken) +
                   ", \"telegramChatId\": " + JStr(o.telegramChatId) +
                   ", \"discordWebhook\": " + JStr(o.discordWebhook) +
                   ", \"ntfyServer\": " + JStr(o.ntfyServer) +
                   ", \"ntfyTopic\": " + JStr(o.ntfyTopic) + " }";
        }

        private static string JStr(string s)
        {
            if (s == null) return "null";
            var sb = new StringBuilder("\"");
            foreach (char c in s)
            {
                switch (c)
                {
                    case '\"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default: sb.Append(c); break;
                }
            }
            sb.Append("\"");
            return sb.ToString();
        }

        private static PasswordConfig ReadPwd(Dictionary<string, object> root, string key)
        {
            if (!root.ContainsKey(key) || !(root[key] is Dictionary<string, object>)) return null;
            var p = (Dictionary<string, object>)root[key];
            return new PasswordConfig
            {
                hash = GetStr(p, "hash", null),
                salt = GetStr(p, "salt", null),
                iterations = GetInt(p, "iterations", 100000)
            };
        }

        private static string GetStr(Dictionary<string, object> d, string k, string def)
        {
            object v; return d.TryGetValue(k, out v) && v != null ? v.ToString() : def;
        }
        private static int GetInt(Dictionary<string, object> d, string k, int def)
        {
            object v; if (!d.TryGetValue(k, out v) || v == null) return def;
            int r; return int.TryParse(v.ToString(), NumberStyles.Any, CultureInfo.InvariantCulture, out r) ? r : def;
        }
        private static double GetDouble(Dictionary<string, object> d, string k, double def)
        {
            object v; if (!d.TryGetValue(k, out v) || v == null) return def;
            double r; return double.TryParse(v.ToString(), NumberStyles.Any, CultureInfo.InvariantCulture, out r) ? r : def;
        }
        private static bool GetBool(Dictionary<string, object> d, string k, bool def)
        {
            object v; if (!d.TryGetValue(k, out v) || v == null) return def;
            bool r; return bool.TryParse(v.ToString(), out r) ? r : def;
        }
    }

    // =========================================================================
    //  Widget 架構（第 6 節）—— 工廠 / 策略模式，符合開放封閉原則。
    // =========================================================================
    internal interface IWidget
    {
        // screen：本元件可用的版面矩形（以表單座標表示，通常為主螢幕區域）。
        void Render(Graphics g, Rectangle screen);
    }

    internal abstract class TextWidgetBase : IWidget
    {
        protected readonly WidgetConfig Cfg;
        protected TextWidgetBase(WidgetConfig cfg) { Cfg = cfg; }

        protected abstract string GetText();

        protected virtual Color TextColor { get { return Color.White; } }

        public void Render(Graphics g, Rectangle screen)
        {
            string text = GetText();
            if (string.IsNullOrEmpty(text)) return;

            int y = ResolveY(Cfg.y, screen);
            using (var font = new Font("Segoe UI", Cfg.fontSize, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var brush = new SolidBrush(TextColor))
            using (var shadow = new SolidBrush(Color.FromArgb(160, 0, 0, 0)))
            using (var fmt = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
            {
                var rect = new RectangleF(screen.Left, y, screen.Width, Cfg.fontSize * 1.6f);
                // 陰影提升於各種背景上的可讀性
                g.DrawString(text, font, shadow, new RectangleF(rect.X + 2, rect.Y + 2, rect.Width, rect.Height), fmt);
                g.DrawString(text, font, brush, rect, fmt);
            }
        }

        // 支援 "30%"（佔螢幕高比例）或 "120"（像素）
        protected static int ResolveY(string y, Rectangle screen)
        {
            if (string.IsNullOrEmpty(y)) return screen.Top + screen.Height / 2;
            y = y.Trim();
            if (y.EndsWith("%"))
            {
                double pct;
                if (double.TryParse(y.Substring(0, y.Length - 1), NumberStyles.Any, CultureInfo.InvariantCulture, out pct))
                    return screen.Top + (int)(screen.Height * pct / 100.0);
            }
            int px;
            if (int.TryParse(y, NumberStyles.Any, CultureInfo.InvariantCulture, out px))
                return screen.Top + px;
            return screen.Top + screen.Height / 2;
        }
    }

    internal sealed class ClockWidget : TextWidgetBase
    {
        public ClockWidget(WidgetConfig c) : base(c) { }
        protected override string GetText()
        {
            string f = string.IsNullOrEmpty(Cfg.format) ? "HH:mm" : Cfg.format;
            return DateTime.Now.ToString(f, CultureInfo.CurrentCulture);
        }
    }

    internal sealed class DateWidget : TextWidgetBase
    {
        public DateWidget(WidgetConfig c) : base(c) { }
        protected override string GetText()
        {
            string f = string.IsNullOrEmpty(Cfg.format) ? "yyyy/MM/dd dddd" : Cfg.format;
            return DateTime.Now.ToString(f, CultureInfo.CurrentCulture);
        }
    }

    internal sealed class TextWidget : TextWidgetBase
    {
        public TextWidget(WidgetConfig c) : base(c) { }
        protected override string GetText() { return Cfg.content; }
    }

    internal sealed class HintWidget : TextWidgetBase
    {
        public HintWidget(WidgetConfig c) : base(c) { }
        protected override Color TextColor { get { return Color.FromArgb(200, 220, 220, 220); } }
        protected override string GetText()
        {
            return string.IsNullOrEmpty(Cfg.content) ? "按任意鍵或點擊以解鎖" : Cfg.content;
        }
    }

    // 天氣元件（第 6 節：預留，預設關閉）。會送出城市名至 wttr.in，故由老爺自行啟用。
    internal sealed class WeatherWidget : TextWidgetBase
    {
        private string _cache = "…";
        private bool _fetching;
        public WeatherWidget(WidgetConfig c) : base(c) { BeginFetch(); }

        protected override Color TextColor { get { return Color.FromArgb(230, 200, 230, 255); } }

        private void BeginFetch()
        {
            if (_fetching || string.IsNullOrEmpty(Cfg.city)) return;
            _fetching = true;
            var t = new Thread(() =>
            {
                try
                {
                    ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; // TLS1.2
                    using (var wc = new WebClient())
                    {
                        wc.Encoding = Encoding.UTF8;
                        // 格式：城市 +溫度，例：Taipei: 26°C
                        string url = "https://wttr.in/" + Uri.EscapeDataString(Cfg.city) + "?format=%l:+%t";
                        _cache = wc.DownloadString(url).Trim();
                    }
                }
                catch { _cache = Cfg.city + ": —"; }
            });
            t.IsBackground = true;
            t.Start();
        }

        protected override string GetText() { return _cache; }
    }

    internal static class WidgetFactory
    {
        public static IWidget Create(WidgetConfig cfg)
        {
            if (cfg == null || !cfg.enabled) return null;
            switch ((cfg.type ?? "").ToLowerInvariant())
            {
                case "clock": return new ClockWidget(cfg);
                case "date": return new DateWidget(cfg);
                case "text": return new TextWidget(cfg);
                case "hint": return new HintWidget(cfg);
                case "weather": return new WeatherWidget(cfg);
                default: return null;   // 未知類型直接忽略
            }
        }
    }

    // 內建時鐘繪製：字級依畫面高度自動縮放，置於畫面中央偏上。
    internal static class ClockRenderer
    {
        public static void Draw(Graphics g, Rectangle screen)
        {
            int fontSize = Math.Max(28, (int)(screen.Height * 0.09));
            var cfg = new WidgetConfig { type = "clock", format = "HH:mm", y = "38%", fontSize = fontSize, enabled = true };
            new ClockWidget(cfg).Render(g, screen);
        }
    }

    // 鎖屏真實事件（供 Guard 終端做因果反應；駭客終端忽略之）
    internal enum TermSignal { KeySuppressed, MouseSuppressed, PanelOpen, VerifyAttempt }

    // 終端特效的共同介面：每種「鎖屏顯示畫面」都實作此方法，
    // LockForm / PreviewPanel 依設定的 terminalStyle 挑選對應實作。
    internal interface ITerminalEffect
    {
        void SetCols(int cols);                              // 依終端區寬度設定每行字數
        void Step();                                         // 推進一影格
        void Render(Graphics g, Rectangle area, float scale);// 繪製到指定區域
        void Signal(TermSignal sig, string detail);          // 接收鎖屏真實事件
    }

    // 依設定的風格字串產生對應的終端特效實作。
    internal static class TerminalFactory
    {
        public static ITerminalEffect Create(string style)
        {
            string s = (style ?? "").Trim().ToLowerInvariant();
            if (s == "guard") return new GuardTerminal();
            return new FakeTerminal();
        }
    }

    // 駭客終端特效：程式即時生成的綠字假指令，不停滾動（純裝飾，不影響安全）。
    internal sealed class FakeTerminal : ITerminalEffect
    {
        // kind: 0 一般(暗綠) 1 成功(亮綠) 2 資訊(青) 3 警告(黃) 4 錯誤(紅) 5 進度
        private sealed class Line { public string Text; public int Kind; }
        private sealed class Cmd { public bool Progress; public bool Instant; public bool Spin; public int Pause; public string Text; public int Kind; public string Label; }

        private readonly List<Line> _lines = new List<Line>();
        private readonly Queue<Cmd> _queue = new Queue<Cmd>();
        private readonly Random _rng = new Random();
        private int _frame;
        private int _cols = 80;        // 每行可容字元數（依螢幕寬度動態設定）
        private int _pauseLeft;        // 停頓剩餘 tick（製造讀取等待感）

        private string _typing;        // 正在打字的整行
        private int _typed;            // 已打出的字元數
        private int _typingKind;
        private bool _inProg;          // 進度條進行中
        private int _prog;
        private string _progLabel = "";
        private int _progStyle;        // 進度條樣式（每次隨機切換，避免單調）

        private bool _inSpin;          // spinner 旋轉等待中
        private int _spinLeft;         // 旋轉剩餘 tick，歸零後定版為 [ OK ]
        private string _spinText = "";

        public FakeTerminal() { EnqueueBanner(); }

        // 由外部依終端區寬度與字寬設定每行可容字元數
        public void SetCols(int cols) { if (cols > 24) _cols = cols; }

        // 駭客終端為純自走式，不對真實事件反應。
        public void Signal(TermSignal sig, string detail) { }

        public void Step()
        {
            _frame++;

            if (_pauseLeft > 0) { _pauseLeft--; return; }   // 讀取等待停頓（游標仍閃）

            if (_typing != null)                       // 逐字打字（少用，營造「輸入指令」感）
            {
                _typed += _rng.Next(2, 6);
                if (_typed >= _typing.Length) { Commit(_typing, _typingKind); _typing = null; }
                return;
            }
            if (_inProg)                               // 進度條原地成長（唯一的「等待%」慢節奏）
            {
                _prog += _rng.Next(4, 16);
                if (_prog >= 100) _prog = 100;
                _lines[_lines.Count - 1].Text = ProgressText(_prog);
                if (_prog >= 100) { _inProg = false; if (_rng.Next(2) == 0) _pauseLeft = _rng.Next(5, 14); }
                else if (_rng.Next(7) == 0) _pauseLeft = _rng.Next(3, 10);   // 偶爾卡在某 %，像在等回應
                return;
            }
            if (_inSpin)                               // spinner 原地旋轉（取代生硬的死等）
            {
                _spinLeft--;
                if (_spinLeft <= 0)
                {
                    _inSpin = false;
                    _lines[_lines.Count - 1].Text = "  [  OK  ]  " + _spinText;
                    _lines[_lines.Count - 1].Kind = 1;
                    if (_rng.Next(3) == 0) _pauseLeft = _rng.Next(4, 12);
                }
                else _lines[_lines.Count - 1].Text = SpinLine(SpinFrames[(_frame / 2) % SpinFrames.Length]);
                return;
            }
            if (_queue.Count == 0) Enqueue();          // 取下一個劇情步驟
            var s = _queue.Dequeue();
            if (s.Spin) { _inSpin = true; _spinLeft = s.Pause; _spinText = s.Text; Commit(SpinLine(SpinFrames[0]), 2); return; }
            if (s.Pause > 0) { _pauseLeft = s.Pause; return; }
            if (s.Instant) { Commit(s.Text, s.Kind); return; }   // 資料狂跑：直接刷出，不逐字
            if (s.Progress) { _inProg = true; _prog = 0; _progLabel = s.Label; _progStyle = _rng.Next(3); Commit(ProgressText(0), 5); }
            else { _typing = s.Text; _typed = 0; _typingKind = s.Kind; }
        }

        private void Commit(string t, int k)
        {
            _lines.Add(new Line { Text = t, Kind = k });
            while (_lines.Count > 80) _lines.RemoveAt(0);
        }

        private string ProgressText(int p)
        {
            int n = 30, f = p * n / 100;
            switch (_progStyle)
            {
                case 1:   // 流動實心方塊
                    return "  " + new string('▰', f) + new string('▱', n - f) + "  " + p.ToString().PadLeft(3) + "%  " + _progLabel;
                case 2:   // 軌道 + 旋轉箭頭，到 100% 收尾
                {
                    bool done = p >= 100;
                    string head = done ? "" : SpinFrames[(_frame / 2) % SpinFrames.Length];
                    int tail = Math.Max(0, n - f - (done ? 0 : 1));
                    return "  " + new string('━', f) + head + new string('·', tail) + "  " + p.ToString().PadLeft(3) + "%  " + _progLabel;
                }
                default:  // 經典 [####----]
                    return "  [" + new string('#', f) + new string('-', n - f) + "] " + p.ToString().PadLeft(3) + "%  " + _progLabel;
            }
        }

        // spinner 旋轉動畫的影格與單行組裝
        private static readonly string[] SpinFrames = { "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" };
        private string SpinLine(string frame) { return "   " + frame + "   " + _spinText; }
        private void QS(string label) { _queue.Enqueue(new Cmd { Spin = true, Pause = _rng.Next(18, 40), Text = label }); }

        private void Q(int kind, string text) { _queue.Enqueue(new Cmd { Instant = true, Text = text, Kind = kind }); }
        private void QP(string label) { _queue.Enqueue(new Cmd { Progress = true, Label = label }); }
        private void QI(int kind, string text) { _queue.Enqueue(new Cmd { Instant = true, Text = text, Kind = kind }); }

        // 多組開場 ASCII LOGO（每次鎖屏隨機挑一組，像 Spring Boot / CLI 工具啟動）
        private static readonly string[][] Logos =
        {
            new[]
            {
                @" ____ _   _ _ _  ____                     _ ",
                @"/ ___| |_(_) | |/ ___|_   _  __ _ _ __ __| |",
                @"\___ \ __| | | | |  _| | | |/ _` | '__/ _` |",
                @" ___) | |_| | | | |_| | |_| | (_| | | | (_| |",
                @"|____/ \__|_|_|_|\____|\__,_|\__,_|_|  \__,_|",
            },
            new[]
            {
                @" ___ _____ ___ _    _    ___ _   _   _   ___ ___  ",
                @"/ __|_   _|_ _| |  | |  / __| | | | /_\ | _ \   \ ",
                @"\__ \ | |  | || |__| |__| (_ | |_| |/ _ \|   / |) |",
                @"|___/ |_| |___|____|____|\___|\___/_/ \_\_|_\___/ ",
            },
            new[]
            {
                @"╔═══════════════════════════════════════╗",
                @"║   ▓▓▓  S T I L L G U A R D  ▓▓▓        ║",
                @"║   ::  secure desktop lock daemon  ::  ║",
                @"╚═══════════════════════════════════════╝",
            },
            new[]
            {
                @" __  ___ _ _ _    ___ _  _ _ _ ___ ___ ",
                @"(_ )|_ _| | | |  /  _) || | /_\ | _ |   \",
                @" _\ \| || | | |_| (_ | || |/ _ \|   | |) )",
                @"(___/|_||_|_|___|\___|\__/_/ \_\_|_|___/ ",
            },
        };

        private void EnqueueBanner()
        {
            QI(0, "");
            foreach (var l in Logos[_rng.Next(Logos.Length)]) QI(10, l);  // 隨機一組 LOGO（品牌橙）
            QI(0, "");
            QI(8, "    secure desktop lock daemon   ·   v1.0");
            QI(9, "    " + new string('─', 40));
            QI(0, "");
            QS("booting StillGuard sentinel");           // spinner 旋轉等待
            QI(1, "[  OK  ] kernel guard module loaded");
            QI(1, "[  OK  ] WH_KEYBOARD_LL / WH_MOUSE_LL hooks engaged");
            QI(1, "[  OK  ] crypto core ready (AES-256-GCM)");
            QS("arming sentinel");
            QI(1, "[+] sentinel ONLINE — monitoring input devices");
            QI(0, "");
        }

        private void QW(int ticks) { _queue.Enqueue(new Cmd { Pause = ticks }); }

        // 把多行內容包進對齊的方框
        private string[] BuildBox(string[] inner)
        {
            int w = 0;
            foreach (var s in inner) if (s.Length > w) w = s.Length;
            var outp = new List<string>();
            outp.Add("╔═" + new string('═', w) + "═╗");
            foreach (var s in inner) outp.Add("║ " + s.PadRight(w) + " ║");
            outp.Add("╚═" + new string('═', w) + "═╝");
            return outp.ToArray();
        }

        // 一行 hex dump（長行，填滿右側）
        private string HexDump()
        {
            // 位元組數依行寬動態調整，讓 hex dump 鋪滿右側（每 byte 約 4 字元 + 位址 12 + 邊框）
            int n = Math.Max(8, Math.Min(48, (_cols - 16) / 4));
            var sb = new StringBuilder();
            sb.Append("0x").Append(Hex(4)).Append("  ");
            var ascii = new StringBuilder();
            for (int i = 0; i < n; i++)
            {
                int b = _rng.Next(0, 256);
                sb.Append(b.ToString("X2")).Append((i % 8 == 7) ? "  " : " ");
                ascii.Append((b >= 32 && b < 127) ? (char)b : '.');
            }
            sb.Append(" |").Append(ascii).Append('|');
            return sb.ToString();
        }

        // 一個埠掃描表格（box-drawing 對齊）
        private string[] BuildPortTable()
        {
            string[][] rows =
            {
                new[]{ "22",   "open",     "ssh    OpenSSH_8.9" },
                new[]{ "80",   "open",     "http   nginx/1.25" },
                new[]{ "443",  "open",     "https  TLS1.3" },
                new[]{ "3306", "filtered", "mysql" },
                new[]{ "8080", "open",     "http-proxy" },
            };
            int c0 = 5, c1 = 9, c2 = 22;
            var L = new List<string>();
            L.Add("┌" + new string('─', c0) + "┬" + new string('─', c1) + "┬" + new string('─', c2) + "┐");
            L.Add("│" + " PORT".PadRight(c0) + "│" + " STATE".PadRight(c1) + "│" + " SERVICE".PadRight(c2) + "│");
            L.Add("├" + new string('─', c0) + "┼" + new string('─', c1) + "┼" + new string('─', c2) + "┤");
            foreach (var r in rows)
                L.Add("│" + (" " + r[0]).PadRight(c0) + "│" + (" " + r[1]).PadRight(c1) + "│" + (" " + r[2]).PadRight(c2) + "│");
            L.Add("└" + new string('─', c0) + "┴" + new string('─', c1) + "┴" + new string('─', c2) + "┘");
            return L.ToArray();
        }

        private string B64(int len)
        {
            const string cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            var sb = new StringBuilder(len);
            for (int i = 0; i < len; i++) sb.Append(cs[_rng.Next(cs.Length)]);
            return sb.ToString();
        }

        // 加權抽取池：畫面豐富型（清單 / 儀表板 / 叢集 / build）與全新圖表型（24~27）
        // 權重加倍，提高多樣圖表登場頻率，讓畫面更熱鬧、形態更分歧
        private static readonly int[] BlockPool =
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
            12, 12, 13, 13, 14, 15, 15, 16, 16,
            17, 18, 19, 20, 21, 22, 23,
            24, 24, 25, 25, 26, 26, 27, 27, 28, 29,
            30, 30, 30,
        };

        // 把一段連貫的劇情排入佇列（看起來像在執行一件完整任務）
        // 每次隨機組裝 2~4 個不同「積木段落」，順序 / 長度 / 樣式每次都不同
        private void Enqueue()
        {
            int blocks = _rng.Next(2, 5);
            int last = -1;
            for (int b = 0; b < blocks; b++)
            {
                int which = BlockPool[_rng.Next(BlockPool.Length)];
                if (which == last) which = BlockPool[_rng.Next(BlockPool.Length)];   // 避免連續重複，重抽一次
                last = which;
                AppendBlock(which);
            }
            // 偶爾插入大段資料狂跑或表格，製造節奏變化
            if (_rng.Next(3) == 0) { foreach (var l in BuildPortTable()) QI(2, l); QI(0, ""); }
        }

        private void AppendBlock(int which)
        {
            string ip = Ip();
            switch (which)
            {
                case 0:
                    Q(0, "$ nmap -sS -p- -T4 " + ip);
                    QW(_rng.Next(10, 24));
                    Q(2, "[*] dispatching SYN probes ...");
                    QP("scanning " + ip + "/24");
                    Q(1, "[+] " + _rng.Next(40, 220) + " hosts up   " + _rng.Next(2, 18) + "." + _rng.Next(10, 99) + "s");
                    DumpBurst(_rng.Next(2, 6));
                    break;
                case 1:
                    Q(0, "$ hydra -l root -P rockyou.txt ssh://" + ip);
                    Q(2, "[*] loading 14,344,392 entries");
                    QW(_rng.Next(12, 30));
                    QP("brute-forcing ssh");
                    Q(3, "[!] lockout — rotating proxy " + Ip() + " -> " + Ip());
                    Q(1, "[+] access granted   root:" + Hex(_rng.Next(3, 7)));
                    break;
                case 2:
                    Q(0, "$ ./tunnel --to " + ip + " --enc aes256-gcm");
                    QS("negotiating handshake");
                    Q(1, "[+] tunnel up   rtt=" + _rng.Next(8, 90) + "ms");
                    QP("exfiltrating payload");
                    DumpBurst(_rng.Next(3, 8));
                    Q(1, "[+] " + _rng.Next(1, 9) + "." + _rng.Next(0, 9) + " GB out   trace wiped");
                    break;
                case 3:
                    Q(0, "$ cryptsetup luksFormat /dev/vault0");
                    Q(2, "[*] deriving master key (PBKDF2 · 600000 iters)");
                    QW(_rng.Next(10, 20));
                    QP("encrypting volume");
                    Q(1, "[+] sealed   sha256:" + Hex(_rng.Next(8, 16)));
                    break;
                case 4:
                    Q(0, "$ guard --audit --deep");
                    Q(2, "[*] scanning " + _rng.Next(200, 9000) + " processes ...");
                    QW(_rng.Next(8, 16));
                    Q(4, "[-] anomaly in pid " + _rng.Next(1000, 9999) + " (" + Pick(Procs) + ")");
                    Q(2, "[*] isolating + terminating ...");
                    Q(1, "[+] threat neutralized");
                    break;
                case 5:
                    Q(2, "[*] dumping memory region 0x" + Hex(4) + " .. 0x" + Hex(4));
                    DumpBurst(_rng.Next(6, 14));     // 大量 hex 全速狂刷
                    break;
                case 6:
                    Q(0, "$ make -j8 guard");
                    for (int i = 0; i < _rng.Next(3, 7); i++)
                        QI(0, "  CC   " + Pick(SrcFiles) + "   (" + _rng.Next(40, 1800) + " loc)");
                    QP("linking objects");
                    Q(1, "[+] build ok   " + _rng.Next(1, 9) + "." + _rng.Next(0, 9) + "s");
                    break;
                case 7:     // git clone（寫實）
                    GitClone();
                    break;
                case 8:
                    Q(0, "$ ./flood --target " + ip + " --threads 5000");
                    Q(2, "[*] spawning worker pool ...");
                    QW(_rng.Next(6, 14));
                    QP("saturating uplink");
                    Q(1, "[+] " + _rng.Next(40, 990) + "k req/s sustained");
                    break;
                case 9:
                    Q(0, "$ ./miner --algo sha256d");
                    for (int i = 0; i < _rng.Next(4, 9); i++)
                        QI(0, "block #" + _rng.Next(800000, 899999) + "  nonce=" + _rng.Next(0, int.MaxValue) + "  " + Hex(_rng.Next(8, 16)));
                    Q(1, "[+] share accepted  diff=" + _rng.Next(1000, 99999));
                    break;
                case 10:
                    Q(0, "$ mysqldump --all-databases > dump.sql");
                    Q(2, "[*] reading schema ...");
                    QW(_rng.Next(6, 12));
                    for (int i = 0; i < _rng.Next(3, 7); i++)
                        QI(0, "  -> " + Pick(Tables) + "   " + _rng.Next(100, 9999999).ToString("N0") + " rows");
                    QP("dumping tables");
                    Q(1, "[+] " + _rng.Next(1, 40) + ".? GB written");
                    break;
                case 11:
                    QS("aligning satellite uplink");
                    QP("locking signal");
                    Q(1, "[+] downlink established  " + _rng.Next(40, 990) + " Mbps");
                    DumpBurst(_rng.Next(3, 7));
                    break;
                case 12:    // 檔案列表（ls -la 風）
                    DirListing();
                    break;
                case 13:    // systemd 服務清單
                    ServiceList();
                    break;
                case 14:    // 資源儀表板（CPU / MEM 長條圖）
                    Dashboard();
                    break;
                case 15:    // 叢集節點上線
                    ClusterSync();
                    break;
                case 16:    // build 流程
                    BuildHooks();
                    break;
                case 17: NpmInstall(); break;       // npm 安裝（寫實）
                case 18: DockerBuild(); break;       // docker build（寫實）
                case 19: AptInstall(); break;        // apt 安裝（寫實）
                case 20: PingHost(); break;          // ping（寫實）
                case 21: KubectlPods(); break;       // kubectl get pods（寫實）
                case 22: PipInstall(); break;        // pip 安裝（寫實）
                case 23: Dmesg(); break;             // dmesg 核心訊息（寫實）
                case 24: NetGraph(); break;          // sparkline 流量走勢圖
                case 25: Histogram(); break;         // 垂直直方圖
                case 26: HeatMap(); break;           // 熱力圖網格
                case 27: PieBreakdown(); break;      // 堆疊比例條 + 圖例
                case 28: LogStream(); break;         // tail -f 日誌串流
                case 29: GitLog(); break;            // git log --graph 分支線圖
                case 30: TopMonitor(); break;        // top 全屏進程監控（高資訊密度列表）
                default:
                    Q(2, "[*] capturing packets on eth0 ...");
                    for (int i = 0; i < _rng.Next(4, 11); i++) QI(0, PacketLine());
                    break;
            }
            QI(0, "");   // 段落間空行
        }

        private static readonly string[] Tables = { "users", "sessions", "auth_tokens", "audit_log", "payments", "keys", "devices", "events" };
        private static readonly string[] DirNames = { ".git", "assets", "components", "node_modules", "pages", "src", "build", "dist", "config", "static", "store" };
        private static readonly string[] FileNames = { "index.ts", "package.json", "README.md", "nuxt.config.js", ".gitignore", "tsconfig.json", "yarn.lock", "main.c", "server.py", "config.yaml", "Dockerfile" };
        private static readonly string[] Svcs = { "sshd", "nginx", "docker", "cron", "systemd-journald", "NetworkManager", "firewalld", "postgresql", "redis", "dbus" };

        // 檔案 / 目錄列出（三種變體：ls -la / du -sh / find），開頭穿插小停頓
        private void DirListing()
        {
            string path = Pick(new[] { "/var/www/app", "/home/user/project", "/opt/guard", "/srv/data" });
            switch (_rng.Next(3))
            {
                case 1:     // du -sh：各目錄大小
                    Q(0, "$ du -sh " + path + "/*");
                    QW(_rng.Next(4, 10));
                    for (int i = 0, dn = _rng.Next(6, 11); i < dn; i++)
                        QI(0, (_rng.Next(1, 9) + "." + _rng.Next(0, 9) + Pick(new[] { "K", "M", "G" })).PadRight(7) + path + "/" + Pick(DirNames));
                    break;
                case 2:     // find：列出檔案路徑
                    Q(0, "$ find " + path + " -type f -name '*." + Pick(new[] { "ts", "py", "c", "json", "log" }) + "'");
                    QW(_rng.Next(4, 9));
                    for (int i = 0, fn = _rng.Next(7, 14); i < fn; i++)
                        QI(0, path + "/" + Pick(DirNames) + "/" + Pick(FileNames));
                    break;
                default:    // ls -la（欄位對齊）
                    Q(0, "$ ls -la " + path);
                    QI(0, "total " + _rng.Next(40, 980));
                    for (int i = 0, n = _rng.Next(7, 14); i < n; i++)
                    {
                        bool dir = _rng.Next(3) == 0;
                        string perm = dir ? "drwxr-xr-x" : "-rw-r--r--";
                        string size = (dir ? 4096 : _rng.Next(64, 900000)).ToString().PadLeft(8);
                        string date = Pick(Months) + " " + _rng.Next(1, 28).ToString().PadLeft(2) + " " + _rng.Next(0, 24).ToString("D2") + ":" + _rng.Next(0, 60).ToString("D2");
                        string name = dir ? Pick(DirNames) : Pick(FileNames);
                        QI(dir ? 2 : 0, perm + " " + _rng.Next(1, 5) + " root root " + size + " " + date + " " + name);
                    }
                    break;
            }
        }

        private static readonly string[] SvcDesc = { "OpenSSH server daemon", "Web server", "Container engine", "Job scheduler", "System logging", "Network manager" };

        // 服務 / 進程列出（三種變體：systemctl list / systemctl status / ps aux）
        private void ServiceList()
        {
            switch (_rng.Next(3))
            {
                case 1:     // systemctl status：單一服務詳情
                {
                    string svc = Pick(Svcs);
                    bool running = _rng.Next(4) != 0;
                    Q(0, "$ systemctl status " + svc);
                    QW(_rng.Next(3, 8));
                    QI(running ? 1 : 4, "● " + svc + ".service - " + Pick(SvcDesc));
                    QI(0, "   Loaded: loaded (/lib/systemd/system/" + svc + ".service; enabled)");
                    QI(running ? 1 : 4, "   Active: " + (running ? "active (running)" : "failed (Result: exit-code)") + " since " + Pick(Months) + " " + _rng.Next(1, 28) + " " + _rng.Next(0, 24).ToString("D2") + ":" + _rng.Next(0, 60).ToString("D2"));
                    QI(0, " Main PID: " + _rng.Next(300, 9999) + " (" + svc + ")");
                    QI(0, "    Tasks: " + _rng.Next(1, 40) + " (limit: 4915)");
                    QI(0, "   Memory: " + _rng.Next(1, 400) + "." + _rng.Next(0, 9) + "M");
                    QI(2, "   CGroup: /system.slice/" + svc + ".service");
                    break;
                }
                case 2:     // ps aux：進程表（依 CPU 排序）
                {
                    Q(0, "$ ps aux --sort=-%cpu | head");
                    QI(2, "USER       PID %CPU %MEM    VSZ   RSS COMMAND");
                    for (int i = 0, n = _rng.Next(6, 11); i < n; i++)
                    {
                        string user = Pick(new[] { "root", "www-data", "postgres", "user", "redis" }).PadRight(9);
                        string pid = _rng.Next(100, 9999).ToString().PadLeft(5);
                        string cpu = (_rng.Next(0, 80) + "." + _rng.Next(0, 9)).PadLeft(4);
                        string mem = (_rng.Next(0, 20) + "." + _rng.Next(0, 9)).PadLeft(4);
                        string vsz = _rng.Next(10000, 999999).ToString().PadLeft(7);
                        string rss = _rng.Next(1000, 99999).ToString().PadLeft(5);
                        QI(0, user + " " + pid + " " + cpu + " " + mem + " " + vsz + " " + rss + " " + Pick(Svcs));
                    }
                    break;
                }
                default:    // systemctl list-units（欄位對齊）
                    Q(0, "$ systemctl list-units --type=service");
                    QI(2, "  UNIT                      LOAD     ACTIVE    SUB        DESCRIPTION");
                    for (int i = 0, n = _rng.Next(6, 11); i < n; i++)
                    {
                        bool running = _rng.Next(3) != 0;
                        string svc = Pick(Svcs) + ".service";
                        QI(running ? 1 : 0, "  " + svc.PadRight(24) + " loaded   " + (running ? "active" : "inactive").PadRight(9) + " " + (running ? "running" : "dead").PadRight(10) + " " + Pick(SvcDesc));
                    }
                    break;
            }
        }

        // 資源儀表板（兩種變體：system monitor / nvidia-smi），每次隨機增列
        private void Dashboard()
        {
            if (_rng.Next(3) == 0)    // nvidia-smi 風 GPU 表
            {
                Q(6, "$ nvidia-smi");
                QI(9, "  ┌─ NVIDIA-SMI ───────────────────────────────┐");
                for (int g = 0, gpus = _rng.Next(1, 5); g < gpus; g++)
                {
                    int u = _rng.Next(0, 100), t = _rng.Next(35, 88);
                    QI(u > 85 || t > 80 ? 4 : u > 60 ? 3 : 1, "  GPU" + g + " " + Pick(new[] { "RTX4090", "A100-80G", "H100", "RTX3080" }).PadRight(9) + " " + t + "°C  [" + Bar(u, 18) + "] " + u.ToString().PadLeft(3) + "%  " + (u * _rng.Next(16, 80) / 100) + "G");
                }
                QI(9, "  └────────────────────────────────────────────┘");
                return;
            }

            QI(8, "  ┌─ system monitor ───────────────────────────┐");
            for (int c = 0, cores = _rng.Next(4, 9); c < cores; c++)
            {
                int p = _rng.Next(0, 100);
                QI(p > 85 ? 4 : p > 60 ? 3 : 1, "  CPU" + c + " [" + Bar(p, 28) + "] " + p.ToString().PadLeft(3) + "%");
            }
            int mp = _rng.Next(30, 95);
            QI(mp > 85 ? 4 : mp > 65 ? 3 : 1, "  MEM  [" + Bar(mp, 28) + "] " + (mp * 32 / 100) + "." + _rng.Next(0, 9) + "/32 GB");
            int np = _rng.Next(0, 60);
            QI(2, "  NET  [" + Bar(np, 28) + "] " + _rng.Next(0, 990) + " Mbps");              // 青
            // 隨機增列 SWAP / DISK I/O / 溫度，讓每次儀表板都不同
            if (_rng.Next(2) == 0) { int sp = _rng.Next(0, 40); QI(6, "  SWAP [" + Bar(sp, 28) + "] " + (sp * 8 / 100) + "." + _rng.Next(0, 9) + "/8 GB"); }   // 藍
            if (_rng.Next(2) == 0) { int dp = _rng.Next(0, 100); QI(7, "  DISK [" + Bar(dp, 28) + "] " + _rng.Next(0, 600) + " MB/s"); }                       // 洋紅
            if (_rng.Next(2) == 0) { int tp = _rng.Next(35, 92); QI(tp > 80 ? 4 : 10, "  TEMP [" + Bar(tp, 28) + "] " + tp + "°C"); }                          // 橙 / 過熱紅
            QI(8, "  └────────────────────────────────────────────┘");
        }

        private static string Bar(int pct, int n)
        {
            int f = pct * n / 100;
            return new string('█', f) + new string('░', n - f);
        }
        private static readonly string[] Months = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
        private static readonly string[] Crates = { "serde", "tokio", "rand", "clap", "regex", "hyper", "anyhow", "log", "syn", "bytes" };
        private static readonly string[] Chunks = { "main", "vendor", "runtime", "app", "polyfills", "styles", "common" };

        // 叢集節點上線（含偶發掉線 → 重連劇情、延遲統計，穿插停頓）
        private void ClusterSync()
        {
            Q(2, "[*] synchronizing botnet ...");
            QW(_rng.Next(8, 16));
            Q(1, "[+] establishing connections " + _rng.Next(800, 1999) + " nodes");
            for (int i = 0, clusters = _rng.Next(5, 12); i < clusters; i++)
            {
                int roll = _rng.Next(8);
                if (roll == 0)        // 掉線 → 重連
                {
                    QI(4, "    Cluster #" + i.ToString("D2") + "  [offline]  — link lost");
                    QW(_rng.Next(3, 8));
                    QI(3, "    Cluster #" + i.ToString("D2") + "  [reconnecting] ...");
                    QI(1, "    Cluster #" + i.ToString("D2") + "  [online]   recovered");
                }
                else
                {
                    bool booting = roll == 1;
                    QI(booting ? 3 : 1, "    Cluster #" + i.ToString("D2") + "  (" + _rng.Next(100, 200) + " nodes)  [" + (booting ? "booting" : "online") + "]   rtt=" + _rng.Next(5, 180) + "ms");
                }
            }
            Q(1, "[+] mesh latency avg " + _rng.Next(8, 60) + "ms   throughput " + _rng.Next(1, 40) + "." + _rng.Next(0, 9) + " Gbps");
            Q(1, "[+] botnet update complete");
        }

        // build 流程（三種變體：mkinitcpio / webpack / cargo）
        private void BuildHooks()
        {
            switch (_rng.Next(3))
            {
                case 1:     // webpack / vite 打包
                    Q(0, "$ npm run build");
                    QI(2, "vite v5.0.0 building for production...");
                    QS("transforming modules");
                    QI(0, "  dist/index.html                  " + _rng.Next(1, 9) + "." + _rng.Next(0, 9) + " kB");
                    foreach (var c in Chunks)
                        if (_rng.Next(3) != 0)
                            QI(0, "  dist/assets/" + c + "-" + Hex(4).ToLower() + ".js   " + _rng.Next(10, 990) + "." + _rng.Next(0, 9) + " kB │ gzip: " + _rng.Next(3, 300) + "." + _rng.Next(0, 9) + " kB");
                    QI(1, "✓ built in " + _rng.Next(1, 40) + "." + _rng.Next(0, 9) + "s");
                    break;
                case 2:     // cargo build
                    Q(0, "$ cargo build --release");
                    for (int i = 0, n = _rng.Next(5, 11); i < n; i++)
                        QI(0, "   Compiling " + Pick(Crates) + " v" + _rng.Next(0, 3) + "." + _rng.Next(0, 20) + "." + _rng.Next(0, 9));
                    QS("compiling guard");
                    QI(1, "    Finished release [optimized] target(s) in " + _rng.Next(4, 90) + "." + _rng.Next(0, 9) + "s");
                    break;
                default:    // mkinitcpio 打包 image（原樣）
                    Q(0, "==> building image  preset: linux");
                    QW(_rng.Next(6, 12));
                    foreach (var h in new[] { "base", "udev", "autodetect", "modconf", "block", "keymap", "encrypt", "fsck", "filesystems" })
                        QI(0, "  -> running build hook [" + h + "]");
                    if (_rng.Next(2) == 0) QI(3, "==> WARNING: possibly missing firmware for module " + Pick(SrcFiles));
                    QP("generating initramfs");
                    Q(1, "[+] image built  " + Hex(8));
                    break;
            }
        }

        private void DumpBurst(int n) { for (int i = 0; i < n; i++) QI(0, HexDump()); }

        private static readonly string[] SrcFiles = { "sentinel.c", "hook.c", "crypto.c", "netfilter.c", "vault.c", "watchdog.c", "ipc.c" };

        // ── 寫實終端積木：日常開發 / 運維會看到的真實輸出（只求「像」） ──────────────
        private static readonly string[] Repos    = { "acme/core", "acme/api", "vendor/sdk", "infra/platform", "web/dashboard", "ops/pipeline" };
        private static readonly string[] NpmPkgs  = { "lodash", "react", "webpack", "axios", "express", "typescript", "eslint", "chalk", "vite", "next" };
        private static readonly string[] Pkgs     = { "nginx", "curl", "git", "htop", "vim", "python3", "nodejs", "redis-server", "postgresql", "build-essential", "tmux", "jq" };
        private static readonly string[] K8sApps  = { "api", "web", "worker", "redis", "postgres", "nginx", "auth", "billing", "scheduler" };
        private static readonly string[] PyPkgs   = { "numpy", "pandas", "requests", "flask", "django", "scipy", "torch", "boto3", "pytest", "pydantic" };
        private string Ver() { return _rng.Next(1, 5) + "." + _rng.Next(0, 20) + "." + _rng.Next(0, 9); }

        private void GitClone()
        {
            string repo = Pick(Repos), name = repo.Substring(repo.IndexOf('/') + 1);
            Q(0, "$ git clone git@github.com:" + repo + ".git");
            QI(0, "Cloning into '" + name + "'...");
            int objs = _rng.Next(8000, 42000);
            QI(0, "remote: Enumerating objects: " + objs + ", done.");
            QI(0, "remote: Counting objects: 100% (" + objs + "/" + objs + "), done.");
            int comp = objs / _rng.Next(3, 5);
            QI(0, "remote: Compressing objects: 100% (" + comp + "/" + comp + "), done.");
            QP("Receiving objects");
            QI(1, "Receiving objects: 100% (" + objs + "/" + objs + "), " + _rng.Next(12, 90) + "." + _rng.Next(0, 9) + " MiB | " + _rng.Next(2, 9) + "." + _rng.Next(0, 9) + " MiB/s, done.");
            int deltas = objs * 2 / 3;
            QI(0, "Resolving deltas: 100% (" + deltas + "/" + deltas + "), done.");
        }

        private void NpmInstall()
        {
            Q(0, "$ npm install");
            QS("resolving packages");
            if (_rng.Next(2) == 0) QI(3, "npm WARN deprecated " + Pick(NpmPkgs) + "@" + Ver() + ": this library is no longer supported");
            int pkgs = _rng.Next(300, 1600);
            QI(1, "added " + pkgs + " packages, and audited " + (pkgs + 1) + " packages in " + _rng.Next(4, 40) + "s");
            QI(0, _rng.Next(40, 200) + " packages are looking for funding");
            QI(1, "found 0 vulnerabilities");
        }

        private void DockerBuild()
        {
            string img = Pick(Repos) + ":latest";
            Q(0, "$ docker build -t " + img + " .");
            int steps = _rng.Next(8, 16);
            QI(2, "Step " + _rng.Next(3, steps) + "/" + steps + " : RUN " + Pick(new[] { "apt-get update", "npm ci", "pip install -r requirements.txt", "go build ./...", "make" }));
            QI(0, " ---> Running in " + Hex(6).ToLower());
            int layers = _rng.Next(4, 9);
            for (int i = 0; i < layers; i++) QI(1, Hex(6).ToLower() + ": Pull complete");
            QS("exporting layers");
            QI(1, "Successfully built " + Hex(6).ToLower());
            QI(1, "Successfully tagged " + img);
        }

        private void AptInstall()
        {
            var picks = new List<string>();
            int k = _rng.Next(2, 5);
            for (int i = 0; i < k; i++) picks.Add(Pick(Pkgs));
            Q(0, "$ sudo apt-get install -y " + picks[0]);
            QI(0, "Reading package lists... Done");
            QI(0, "Building dependency tree... Done");
            QI(0, "The following NEW packages will be installed:");
            QI(2, "  " + string.Join(" ", picks));
            foreach (var p in picks) QI(0, "Unpacking " + p + " (" + Ver() + ") ...");
            foreach (var p in picks) QI(1, "Setting up " + p + " (" + Ver() + ") ...");
            QI(0, "Processing triggers for man-db (2.9.4-2) ...");
        }

        private void PingHost()
        {
            string ip = Pick(new[] { "1.1.1.1", "8.8.8.8", Ip(), Ip() });
            int n = _rng.Next(4, 8);
            Q(0, "$ ping -c " + n + " " + ip);
            QI(0, "PING " + ip + " (" + ip + ") 56(84) bytes of data.");
            for (int i = 1; i <= n; i++)
                QI(1, "64 bytes from " + ip + ": icmp_seq=" + i + " ttl=" + _rng.Next(48, 64) + " time=" + _rng.Next(1, 80) + "." + _rng.Next(0, 9) + " ms");
            QI(2, "--- " + ip + " ping statistics ---");
            QI(0, n + " packets transmitted, " + n + " received, 0% packet loss");
        }

        private void KubectlPods()
        {
            Q(0, "$ kubectl get pods -n " + Pick(new[] { "production", "staging", "default", "kube-system" }));
            QI(2, "NAME".PadRight(30) + "READY   STATUS      RESTARTS   AGE");
            int n = _rng.Next(5, 10);
            for (int i = 0; i < n; i++)
            {
                bool ok = _rng.Next(6) != 0;
                string name = (Pick(K8sApps) + "-" + Hex(3).ToLower() + "-" + Hex(2).ToLower()).PadRight(30);
                string status = (ok ? "Running" : Pick(new[] { "Pending", "CrashLoopBackOff", "ContainerCreating" })).PadRight(11);
                QI(ok ? 1 : 3, name + (ok ? "1/1" : "0/1") + "     " + status + " " + _rng.Next(0, 5) + "          " + _rng.Next(1, 30) + Pick(new[] { "d", "h", "m" }));
            }
        }

        private void PipInstall()
        {
            Q(0, "$ pip install -r requirements.txt");
            int n = _rng.Next(3, 6);
            var got = new List<string>();
            for (int i = 0; i < n; i++)
            {
                string p = Pick(PyPkgs);
                got.Add(p);
                QI(0, "Collecting " + p + "==" + Ver());
                QI(0, "  Downloading " + p + "-" + Ver() + "-cp311.whl (" + _rng.Next(1, 80) + "." + _rng.Next(0, 9) + " MB)");
            }
            QS("installing collected packages");
            QI(1, "Successfully installed " + string.Join(" ", got));
        }

        private void Dmesg()
        {
            Q(0, "$ dmesg -w");
            int n = _rng.Next(5, 10), t = _rng.Next(1000, 9000);
            for (int i = 0; i < n; i++)
            {
                t += _rng.Next(1, 200);
                string msg = Pick(new[]
                {
                    "usb " + _rng.Next(1, 5) + "-" + _rng.Next(1, 9) + ": new high-speed USB device number " + _rng.Next(2, 30),
                    "EXT4-fs (sda" + _rng.Next(1, 5) + "): mounted filesystem with ordered data mode",
                    "eth0: link up, 1000 Mbps, full duplex",
                    "audit: type=1400 apparmor=\"STATUS\" operation=\"profile_load\"",
                    "CPU" + _rng.Next(0, 8) + ": Core temperature above threshold, cpu clock throttled",
                    "TCP: request_sock_TCP: Possible SYN flooding on port " + _rng.Next(80, 9000),
                });
                int kind = (msg.Contains("throttled") || msg.Contains("flooding")) ? 3 : 0;
                QI(kind, "[" + (t / 1000) + "." + (t % 1000).ToString("D3") + "] " + msg);
            }
        }

        // ── 全新形態圖表：打破「水平長條圖」單一視覺 ──────────────────────────────
        private static readonly char[] Spark = { '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█' };
        private static readonly char[] Heat  = { '·', '░', '▒', '▓', '█' };

        // 隨機漫步產生較平滑的走勢曲線（非純雜訊）
        private string SparkWalk(int n)
        {
            var sb = new StringBuilder(n);
            int v = _rng.Next(0, 8);
            for (int i = 0; i < n; i++)
            {
                v += _rng.Next(-2, 3);
                if (v < 0) v = 0; else if (v > 7) v = 7;
                sb.Append(Spark[v]);
            }
            return sb.ToString();
        }
        private int GraphW(int max) { return Math.Min(max, Math.Max(20, _cols - 16)); }

        // ① sparkline 流量走勢圖
        private void NetGraph()
        {
            Q(6, "$ bmon -p eth0");
            QI(9, "  ┌─ traffic eth0  (last 60s) ──────────────────┐");
            int w = GraphW(46);
            QI(2, "  RX  " + SparkWalk(w) + "  " + _rng.Next(10, 990) + " Mbps");   // 青
            QI(6, "  TX  " + SparkWalk(w) + "  " + _rng.Next(10, 990) + " Mbps");   // 藍
            QI(7, "  pps " + SparkWalk(w) + "  " + _rng.Next(1, 99) + "k");         // 洋紅
            QI(9, "  └────────────────────────────────────────────┘");
        }

        // ② 垂直直方圖（鐘形分佈感）
        private void Histogram()
        {
            Q(6, "$ guard --latency-histogram");
            QI(8, "  request latency distribution");
            int cols = _rng.Next(12, 20);
            int[] h = new int[cols];
            for (int i = 0; i < cols; i++)
            {
                int bell = (i > cols / 4 && i < cols * 3 / 4) ? _rng.Next(2, 5) : 0;
                h[i] = Math.Min(8, _rng.Next(0, 5) + bell);
            }
            for (int row = 8; row >= 1; row--)
            {
                var sb = new StringBuilder("  ");
                for (int i = 0; i < cols; i++) sb.Append(h[i] >= row ? "█ " : "  ");
                int rk = row >= 7 ? 4 : row >= 5 ? 3 : 1;   // 熱度漸層：頂紅 → 中黃 → 底綠
                QI(rk, sb.ToString());
            }
            QI(9, "  0   25  50  100 250 500  1s  2s+  (ms)");
        }

        // ③ 熱力圖網格（7d × 連線密度）
        private void HeatMap()
        {
            Q(6, "$ guard --activity-map");
            QI(8, "  connection heatmap  (last 7 days)");
            int w = GraphW(46);
            string[] days = { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
            for (int d = 0; d < 7; d++)
            {
                var sb = new StringBuilder("  " + days[d] + " ");
                for (int x = 0; x < w; x++) sb.Append(Heat[_rng.Next(0, 5)]);
                QI(5, sb.ToString());   // teal 網格
            }
            QI(9, "      less " + new string(Heat[0], 1) + Heat[1] + Heat[2] + Heat[3] + Heat[4] + " more");
        }

        // ④ 堆疊比例條 + 圖例
        private void PieBreakdown()
        {
            Q(6, "$ df -h /dev/vault0 | guard-chart");
            string[] cats = { "system", "data", "logs", "cache", "free" };
            char[] blk = { '█', '▓', '▒', '░', ' ' };
            int[] lk = { 6, 1, 3, 7, 9 };   // 圖例分類色：藍 / 綠 / 黃 / 洋紅 / 灰
            int[] pct = new int[cats.Length];
            int rem = 100;
            for (int i = 0; i < cats.Length - 1; i++) { pct[i] = _rng.Next(5, Math.Max(6, rem - (cats.Length - i - 1) * 5)); rem -= pct[i]; }
            pct[cats.Length - 1] = rem;
            int barW = GraphW(44);
            var bar = new StringBuilder("  ");
            for (int i = 0; i < cats.Length; i++) bar.Append(new string(blk[i], Math.Max(0, pct[i] * barW / 100)));
            QI(8, "  storage usage  /dev/vault0  (" + _rng.Next(200, 900) + " GB)");
            QI(8, "  " + bar.ToString().TrimStart().PadRight(barW, blk[cats.Length - 2]));
            for (int i = 0; i < cats.Length; i++)
                QI(lk[i], "  " + (blk[i] == ' ' ? '░' : blk[i]) + "  " + cats[i].PadRight(8) + pct[i].ToString().PadLeft(3) + "%");
        }

        // ⑤ tail -f 日誌串流（HTTP 狀態碼著色）
        private static readonly string[] LogPaths = { "/", "/api/v1/users", "/login", "/static/app.js", "/health", "/api/v1/orders", "/favicon.ico", "/admin", "/assets/main.css" };
        private void LogStream()
        {
            Q(6, "$ tail -f /var/log/nginx/access.log");
            int[] codes = { 200, 200, 200, 200, 301, 304, 404, 500, 403 };
            for (int i = 0, n = _rng.Next(7, 14); i < n; i++)
            {
                int code = codes[_rng.Next(codes.Length)];
                int kind = code < 300 ? 1 : code < 400 ? 2 : code < 500 ? 3 : 4;
                QI(kind, Ip() + " - [" + _rng.Next(1, 28).ToString("D2") + "/" + Pick(Months) + ":" + _rng.Next(0, 24).ToString("D2") + ":" + _rng.Next(0, 60).ToString("D2") + "] \"" +
                    Pick(new[] { "GET", "GET", "POST", "PUT", "DELETE" }) + " " + Pick(LogPaths) + "\" " + code + " " + _rng.Next(120, 99999));
            }
        }

        // ⑥ git log --graph 分支線圖
        private static readonly string[] GitMsgs = { "merge branch 'feature/auth'", "fix: null deref in hook", "refactor crypto core", "bump deps", "add ci pipeline", "wip: dashboard", "hotfix: lockout", "docs: update readme", "perf: cache hot path" };
        private void GitLog()
        {
            Q(6, "$ git log --oneline --graph --all");
            string[] rails = { "* ", "* ", "│ ", "├─┐ ", "│ * ", "* │ ", "│╱ ", "├─┘ " };
            for (int i = 0, n = _rng.Next(8, 14); i < n; i++)
            {
                string r = rails[_rng.Next(rails.Length)];
                if (r.Contains("*")) QI(3, r + Hex(4).ToLower() + " " + Pick(GitMsgs));   // 黃 commit 雜湊
                else QI(9, r);                                                            // 灰 分支線
            }
        }

        // ── top 風格全屏進程監控（高資訊密度列表，仿 macOS top） ──────────────────
        private static readonly string[] TopProcs =
        {
            "kernel_task", "launchd", "WindowServer", "Terminal", "top", "bash", "login", "Finder",
            "Safari", "Dock", "mds", "mdworker", "coreaudiod", "cupsd", "quicklookd", "automountd",
            "CVMCompiler", "xpchelper", "screencapture", "Spotlight", "syslogd", "configd", "powerd",
            "bluetoothd", "imklaunchage", "launchdadd", "distnoted", "fseventsd", "hidd",
        };
        private string D2() { return _rng.Next(0, 100).ToString("D2"); }
        private string Dec2() { return _rng.Next(0, 3) + "." + D2(); }
        private string Clock() { return _rng.Next(0, 24).ToString("D2") + ":" + D2() + ":" + D2(); }
        private string Mem()   // 隨機記憶體量，K / M 並偶帶 + 號（仿 top）
        {
            string plus = _rng.Next(2) == 0 ? "+" : "";
            return (_rng.Next(4) == 0 ? _rng.Next(1, 99) + "M" : _rng.Next(120, 9999) + "K") + plus;
        }

        private void TopMonitor()
        {
            Q(6, "$ top -l 1");
            int total = _rng.Next(180, 320), run = _rng.Next(1, 5), stuck = _rng.Next(0, 3);
            QI(8, "Processes: " + total + " total, " + run + " running, " + stuck + " stuck, " + (total - run - stuck) + " sleeping, " + _rng.Next(800, 1900) + " threads   " + Clock());
            int u = _rng.Next(2, 35), s = _rng.Next(2, 25);
            QI(2, "Load Avg: " + Dec2() + ", " + Dec2() + ", " + Dec2() + "  CPU usage: " + u + "." + D2() + "% user, " + s + "." + D2() + "% sys, " + (100 - u - s) + "." + D2() + "% idle");
            QI(9, "SharedLibs: " + _rng.Next(8, 40) + "M resident, " + _rng.Next(1000, 9000) + "K data, 0B linkedit.");
            QI(9, "MemRegions: " + _rng.Next(8000, 30000) + " total, " + _rng.Next(200, 900) + "M resident, " + _rng.Next(20, 90) + "M private, " + _rng.Next(100, 400) + "M shared.");
            QI(3, "PhysMem: " + _rng.Next(100, 400) + "M wired, " + _rng.Next(800, 2400) + "M active, " + _rng.Next(200, 900) + "M inactive, " + _rng.Next(1500, 3500) + "M used, " + _rng.Next(100, 600) + "M free.");
            QI(6, "VM: " + _rng.Next(100, 400) + "G vsize, " + _rng.Next(800, 1500) + "M framework vsize, " + _rng.Next(100000, 200000) + "(0) pageins, " + _rng.Next(100, 900) + "(0) pageouts.");
            QI(2, "Networks: packets: " + _rng.Next(1000000, 3000000) + "/" + _rng.Next(100, 1900) + "M in, " + _rng.Next(1000000, 3000000) + "/" + _rng.Next(100, 900) + "M out.");
            QI(7, "Disks: " + _rng.Next(100000, 200000) + "/" + _rng.Next(1000, 5000) + "M read, " + _rng.Next(100000, 200000) + "/" + _rng.Next(1000, 6000) + "M written.");
            QI(0, "");
            QI(8, "PID    COMMAND       %CPU TIME     #TH #WQ #POR #MRE RPRVT  RSHRD RSIZE");
            for (int i = 0, n = _rng.Next(12, 20); i < n; i++)
            {
                bool busy = _rng.Next(8) == 0;
                string pid = _rng.Next(100, 99999).ToString().PadRight(6);
                string cmd = Pick(TopProcs);
                if (cmd.Length > 13) cmd = cmd.Substring(0, 13);
                cmd = cmd.PadRight(13);
                string cpu = (busy ? _rng.Next(1, 40) + "." + _rng.Next(0, 9) : "0.0").PadRight(4);
                string time = "00:" + D2() + "." + D2();
                string th = _rng.Next(1, 12).ToString().PadRight(3);
                string wq = _rng.Next(0, 4).ToString().PadRight(3);
                string por = (_rng.Next(20, 200) + (_rng.Next(2) == 0 ? "+" : "")).PadRight(4);
                string mre = (_rng.Next(40, 200) + (_rng.Next(2) == 0 ? "+" : "")).PadRight(4);
                QI(busy ? 1 : 0, pid + " " + cmd + " " + cpu + " " + time + " " + th + " " + wq + " " + por + " " + mre + " " + Mem().PadRight(6) + " " + Mem().PadRight(5) + " " + Mem());
            }
        }

        private string PacketLine()
        {
            string proto = Pick(new[] { "TCP", "UDP", "TLS", "ICMP" });
            return _rng.Next(10, 24) + ":" + _rng.Next(10, 60).ToString("D2") + ":" + _rng.Next(10, 60).ToString("D2") + "." + _rng.Next(100, 999) +
                   "  " + Ip() + ":" + _rng.Next(1024, 65535) + " -> " + Ip() + ":" + _rng.Next(1, 1024) +
                   "  " + proto + "  len=" + _rng.Next(40, 1460) + "  seq=0x" + Hex(4);
        }

        private static readonly string[] Procs = { "svchost", "lsass", "rundll32", "powershell", "wmic", "cmd", "explorer" };
        private string Pick(string[] a) { return a[_rng.Next(a.Length)]; }
        private string Ip() { return _rng.Next(1, 255) + "." + _rng.Next(0, 256) + "." + _rng.Next(0, 256) + "." + _rng.Next(1, 255); }
        private string Hex(int bytes)
        {
            var sb = new StringBuilder(bytes * 2);
            for (int i = 0; i < bytes; i++) sb.Append(_rng.Next(0, 256).ToString("X2"));
            return sb.ToString();
        }

        private const int Palette = 11;     // 調色盤色數（語意分類）
        private static Color ColorFor(int kind)
        {
            switch (kind)
            {
                case 1:  return Color.FromArgb(235, 90, 255, 130);   // 成功    亮綠
                case 2:  return Color.FromArgb(228, 95, 215, 255);   // 資訊    青
                case 3:  return Color.FromArgb(235, 245, 210, 80);   // 警告    黃
                case 4:  return Color.FromArgb(240, 255, 95, 95);    // 錯誤    紅
                case 5:  return Color.FromArgb(235, 80, 230, 205);   // 進度    藍綠 teal
                case 6:  return Color.FromArgb(232, 110, 165, 255);  // 路徑/提示符 藍
                case 7:  return Color.FromArgb(230, 225, 130, 240);  // 數值/雜湊   洋紅
                case 8:  return Color.FromArgb(242, 235, 240, 245);  // 標題/表頭   亮白
                case 9:  return Color.FromArgb(195, 140, 150, 150);  // 次要/註解   灰
                case 10: return Color.FromArgb(238, 255, 175, 70);   // 品牌/強調   橙
                default: return Color.FromArgb(215, 200, 210, 195);  // 一般    中性淺灰白
            }
        }

        // 圓角矩形路徑（四角皆圓）
        private static GraphicsPath RoundedRect(Rectangle r, int rad)
        {
            var p = new GraphicsPath();
            int d = rad * 2;
            if (d <= 0 || d > r.Width || d > r.Height) { p.AddRectangle(r); return p; }
            p.AddArc(r.Left, r.Top, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Top, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.Left, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }
        // 僅上方兩角為圓（標題列用）
        private static GraphicsPath RoundedRectTop(Rectangle r, int rad)
        {
            var p = new GraphicsPath();
            int d = rad * 2;
            p.AddArc(r.Left, r.Top, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Top, d, d, 270, 90);
            p.AddLine(r.Right, r.Top + rad, r.Right, r.Bottom);
            p.AddLine(r.Right, r.Bottom, r.Left, r.Bottom);
            p.CloseFigure();
            return p;
        }
        private static void DrawDot(Graphics g, int x, int y, int dia, Color c)
        {
            using (var b = new SolidBrush(c)) g.FillEllipse(b, x, y, dia, dia);
        }

        public void Render(Graphics g, Rectangle area, float scale)
        {
            int fontPx = Math.Max(11, (int)(12 * scale));
            int lineH = (int)(fontPx * 1.3);
            int pad = (int)(14 * scale);
            int titleH = Math.Max(22, (int)(28 * scale));
            int radius = Math.Max(6, (int)(10 * scale));

            // ── macOS Terminal 風視窗 chrome ──────────────────────────────────
            var prevSmooth = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            using (var path = RoundedRect(area, radius))
            using (var body = new SolidBrush(Color.FromArgb(214, 12, 16, 14)))   // 內容底色（半透）
            using (var border = new Pen(Color.FromArgb(180, 90, 98, 100), Math.Max(1f, scale)))
            {
                g.FillPath(body, path);
                g.DrawPath(border, path);
            }

            var titleRect = new Rectangle(area.Left, area.Top, area.Width, titleH);
            using (var tpath = RoundedRectTop(titleRect, radius))
            using (var tbg = new LinearGradientBrush(titleRect, Color.FromArgb(240, 66, 68, 74), Color.FromArgb(240, 44, 46, 52), LinearGradientMode.Vertical))
                g.FillPath(tbg, tpath);

            // 紅 / 黃 / 綠 三燈
            int dia = Math.Max(8, (int)(12 * scale));
            int dy = area.Top + (titleH - dia) / 2;
            int dx = area.Left + (int)(16 * scale);
            int gap = dia + (int)(8 * scale);
            DrawDot(g, dx, dy, dia, Color.FromArgb(255, 95, 86));
            DrawDot(g, dx + gap, dy, dia, Color.FromArgb(255, 189, 46));
            DrawDot(g, dx + gap * 2, dy, dia, Color.FromArgb(39, 201, 63));
            g.SmoothingMode = prevSmooth;

            // 內容區（標題列下方，左右內縮）
            var content = new Rectangle(area.Left, area.Top + titleH, area.Width, area.Height - titleH);

            // 顯示清單 = 已完成行 + 正在打字的行
            var disp = new List<Line>(_lines);
            if (_typing != null)
                disp.Add(new Line { Text = _typing.Substring(0, Math.Min(_typed, _typing.Length)), Kind = _typingKind });

            int vis = Math.Max(1, (content.Height - pad * 2) / lineH);
            int start = Math.Max(0, disp.Count - vis);

            // 置中標題列文字（顯示視窗尺寸，仿截圖的 80×24）
            using (var tFont = new Font("Segoe UI Semibold", Math.Max(9f, 10f * scale), FontStyle.Regular, GraphicsUnit.Point))
            using (var tBrush = new SolidBrush(Color.FromArgb(230, 205, 208, 212)))
            using (var tFmt = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                g.DrawString("StillGuard — zsh — " + _cols + "×" + vis, tFont, tBrush, new RectangleF(area.Left, area.Top, area.Width, titleH), tFmt);

            var brushes = new SolidBrush[Palette];
            for (int k = 0; k < Palette; k++) brushes[k] = new SolidBrush(ColorFor(k));
            var savedClip = g.Clip;                       // 限制長行只在內容區內，超出裁切
            g.IntersectClip(content);
            using (var font = new Font("Consolas", fontPx, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var fmt = new StringFormat(StringFormatFlags.NoWrap))
            {
                int y = content.Top + pad;
                for (int i = start; i < disp.Count; i++)
                {
                    var ln = disp[i];
                    g.DrawString(ln.Text, font, brushes[ln.Kind % Palette], content.Left + pad, y, fmt);
                    y += lineH;
                }
                if (_frame % 8 < 5 && disp.Count > 0)   // 閃爍游標
                {
                    string lastLine = disp[disp.Count - 1].Text;
                    float w = g.MeasureString(lastLine, font, int.MaxValue, fmt).Width;
                    g.DrawString("_", font, brushes[1], content.Left + pad + w, y - lineH, fmt);
                }
            }
            g.Clip = savedClip;
            for (int k = 0; k < Palette; k++) brushes[k].Dispose();
        }
    }

    // =========================================================================
    //  仿真守護終端（Guard Mode）
    //  以「劇情段（scenario）」為單位產生貼合 StillGuard 功能的擬真 log，
    //  具生命週期（Boot → Guarding → InputShield → Unlock → OTP）與因果關係，
    //  uptime / frameId / sector / 攔截計數等數值持續遞增。純裝飾，不影響安全。
    //  敏感資訊一律遮蔽：密碼僅顯示 masked=true、OTP 顯示 OTP-XXXX、token 顯示 bot***。
    // =========================================================================
    internal sealed class GuardTerminal : ITerminalEffect
    {
        // Level：0 INFO  1 DATA  2 EVENT  3 WARN  4 TRACE  5 ERROR
        private sealed class Line { public string Time; public int Level; public string Ns; public string Msg; }
        private sealed class Pending { public int Level; public string Ns; public string Msg; }

        private readonly List<Line> _lines = new List<Line>();
        private readonly Queue<Pending> _queue = new Queue<Pending>();
        private readonly Random _rng = new Random();

        private int _frame;
        private int _cols = 80;
        private int _waitTicks;             // 逐行節奏：剩餘等待 tick（每 tick≈32ms）

        // ── 連續遞增狀態（讓數值看起來像真的在累積）──
        private readonly DateTime _base;    // 模擬時鐘基準
        private double _simMs;              // 自基準起的模擬毫秒（每行隨機推進 80~280ms）
        private double _bootDoneMs;         // 進入 GUARDING 的模擬時刻（算 uptime 用）
        private bool _booted;
        private int _sector = 1;
        private int _frameId = 1;
        private int _block = 1;
        private int _suppressedKb;
        private int _suppressedMs;
        private int _capturedUnlock;
        private int _attempts;

        // 真實事件反應（鍵鼠與面板）
        private readonly Queue<Pending> _priority = new Queue<Pending>();   // 事件行優先於常態劇情顯示
        private bool _externallyDriven;     // 收到過真實事件 → 停用自走的輸入/解鎖劇情，改由事件驅動
        private int _lastInjFrame = -100;   // 上次插入事件行的影格（節流，避免洗版）
        private int _lastMouseFrame = -100; // 上次計入滑鼠移動的影格（節流）
        private int _keysSinceCounter;      // 距上次輸出 input.counter 的擊鍵數

        // 開機橫幅用的固定參數
        private readonly int _pid;
        private readonly int _scrW;
        private readonly int _scrH;
        private readonly string _sessionId;

        public GuardTerminal()
        {
            _base = DateTime.Now;
            _pid = _rng.Next(2000, 30000);
            try { var b = Screen.PrimaryScreen.Bounds; _scrW = b.Width; _scrH = b.Height; }
            catch { _scrW = 2560; _scrH = 1440; }
            _sessionId = "SG-" + _base.ToString("yyyyMMdd-HHmmss");
            EnqueueBoot();
        }

        public void SetCols(int cols) { if (cols > 24) _cols = cols; }

        public void Step()
        {
            _frame++;
            if (_waitTicks > 0) { _waitTicks--; return; }

            Pending p = null;
            if (_priority.Count > 0) p = _priority.Dequeue();    // 真實事件行優先顯示
            else
            {
                if (_queue.Count == 0) ChooseScenario();
                if (_queue.Count > 0) p = _queue.Dequeue();
            }
            if (p == null) return;

            _lines.Add(new Line { Time = TimeStamp(), Level = p.Level, Ns = p.Ns, Msg = p.Msg });
            while (_lines.Count > 140) _lines.RemoveAt(0);

            _simMs += _rng.Next(80, 281);                 // 模擬時鐘推進
            _waitTicks = _priority.Count > 0 ? 1 : _rng.Next(2, 9);   // 事件連發時加快，常態約 64~288ms 一行
            if (_priority.Count == 0 && _rng.Next(9) == 0) _waitTicks = _rng.Next(15, 38);   // 偶爾停頓（讀取等待感）
        }

        // ── 真實事件反應（由 LockForm 在鍵鼠鉤子 / 面板狀態變化時呼叫）──
        public void Signal(TermSignal sig, string detail)
        {
            _externallyDriven = true;
            switch (sig)
            {
                case TermSignal.KeySuppressed:
                    _suppressedKb++;
                    if (CanInject()) { QF(2, "input.keyboard", "key=VK_" + Vk() + " action=SUPPRESSED source=physical"); _lastInjFrame = _frame; }
                    if (++_keysSinceCounter >= 4) { _keysSinceCounter = 0; QF(0, "input.counter", "suppressedKeyboard=" + _suppressedKb + " suppressedMouse=" + _suppressedMs + " capturedUnlockInput=" + _capturedUnlock); }
                    Prompt();
                    break;

                case TermSignal.MouseSuppressed:
                    bool isMove = string.IsNullOrEmpty(detail) || detail == "move";
                    if (isMove) { if (_frame - _lastMouseFrame < 3) return; _lastMouseFrame = _frame; }   // 移動節流，避免計數暴衝
                    _suppressedMs++;
                    if (CanInject())
                    {
                        if (isMove) QF(2, "input.mouse", "dx=" + _rng.Next(-40, 41) + " dy=" + _rng.Next(-40, 41) + " action=SUPPRESSED");
                        else QF(2, "input.mouse", "button=" + detail + " action=SUPPRESSED");
                        _lastInjFrame = _frame;
                    }
                    Prompt();
                    break;

                case TermSignal.PanelOpen:
                    QF(0, "panel.unlock", "unlock panel requested trigger=" + (string.IsNullOrEmpty(detail) ? "keyboard" : detail));
                    QF(0, "panel.unlock", "input focus moved to secure password field");
                    Prompt();
                    break;

                case TermSignal.VerifyAttempt:
                    _capturedUnlock++;
                    int len; if (!int.TryParse(detail, out len) || len <= 0) len = _rng.Next(4, 13);
                    QF(2, "input.keyboard", "key=ENTER action=CAPTURED target=unlock-panel");
                    QF(0, "auth.session", "password buffer updated length=" + len + " masked=true");
                    QF(0, "auth.verify", "verifying password challenge session=" + _sessionId.Substring(3));
                    _attempts++;
                    QF(3, "auth.verify", "unlock attempt failed reason=HASH_MISMATCH attempts=" + _attempts);
                    QF(0, "auth.session", "password buffer cleared");
                    Prompt();
                    break;
            }
        }

        private void QF(int level, string ns, string msg) { _priority.Enqueue(new Pending { Level = level, Ns = ns, Msg = msg }); }
        private bool CanInject() { return _frame - _lastInjFrame >= 2; }   // 約 64ms 一行，避免洗版
        private void Prompt() { _waitTicks = 0; }                          // 事件行盡快顯示

        // ── 依目前生命週期挑選下一段劇情並排入佇列 ──
        private void ChooseScenario()
        {
            if (!_booted) { _booted = true; _bootDoneMs = _simMs; EnqueueIdle(); return; }

            // 已接上真實事件：輸入攔截 / 解鎖劇情改由實際鍵鼠與面板觸發，
            // 自走劇情僅保留常態守護資訊與偶發 OTP，達成「平常守護、碰鍵鼠才湧出對應 log」的因果感。
            if (_externallyDriven)
            {
                if (_rng.Next(100) < 2) { EnqueueOtp(); return; }   // OTP 維持自走（偶發）
                int g = _rng.Next(100);
                if (g < 45) EnqueueIdle();
                else if (g < 72) EnqueuePipeline();
                else if (g < 86) EnqueueDiag();
                else if (g < 96) EnqueueCyber();
                else EnqueueProgress();
                return;
            }

            int r = _rng.Next(100);
            if (r < 8) { EnqueueInputShield(); return; }       // 偵測到鍵鼠輸入
            if (r < 12) { EnqueueUnlock(); return; }            // 解鎖面板開啟→驗證失敗
            if (r < 14) { EnqueueOtp(); return; }               // F2 / OTP 救援

            int w = _rng.Next(100);                             // GUARDING 常態權重（預覽用，無真實事件）
            if (w < 40) EnqueueIdle();
            else if (w < 65) EnqueuePipeline();
            else if (w < 80) EnqueueDiag();
            else if (w < 92) EnqueueCyber();
            else EnqueueProgress();
        }

        private void Q(int level, string ns, string msg) { _queue.Enqueue(new Pending { Level = level, Ns = ns, Msg = msg }); }

        // ── Boot：啟動與初始化 ──
        private void EnqueueBoot()
        {
            Q(0, "boot.loader", "StillGuard runtime bootstrap started");
            Q(0, "boot.env", "os=Windows " + OsVer() + " arch=x64 session=interactive");
            Q(0, "boot.process", "process=StillGuard.exe pid=" + _pid + " integrity=Medium");
            Q(0, "config.loader", "loading profile from ./stillguard.config.json");
            Q(0, "config.loader", "profile loaded theme=terminal-guard blur=18 dim=0.42");
            Q(0, "display.probe", "primaryMonitor=DISPLAY1 bounds=0,0," + _scrW + "," + _scrH + " scale=125%");
            Q(0, "display.capture", "desktop frame captured width=" + _scrW + " height=" + _scrH + " format=BGRA32");
            Q(0, "visual.pipeline", "stage=blur radius=18 status=READY");
            Q(0, "visual.pipeline", "stage=dim opacity=0.42 status=READY");
            Q(0, "visual.pipeline", "stage=terminal_overlay opacity=0.78 status=READY");
            Q(0, "crypto.verifier", "password verifier initialized algorithm=PBKDF2-SHA256 iterations=100000");
            Q(0, "crypto.random", "secure random provider=Windows-CNG status=READY");
            Q(0, "notifier.router", "channels loaded telegram=ON discord=OFF ntfy=ON");
            Q(0, "hook.keyboard", "low-level keyboard hook installed id=KBD-LL-" + Hex(2) + " mode=exclusive");
            Q(0, "hook.mouse", "low-level mouse hook installed id=MSE-LL-" + Hex(2) + " mode=exclusive");
            Q(0, "session.guard", "guard session created id=" + _sessionId);
            Q(0, "session.guard", "lock state changed UNLOCKED -> GUARDING");
            Q(0, "terminal.renderer", "terminal stream attached maxLines=120 tick=160ms");
        }

        // ── Idle：常駐監控心跳與資料處理 ──
        private void EnqueueIdle()
        {
            Q(0, "monitor.heartbeat", "state=GUARDING uptime=" + Uptime() + " cpu=" + Cpu() + "% memory=" + Mem() + "MB");
            int n = _rng.Next(2, 6);
            for (int i = 0; i < n; i++)
            {
                switch (_rng.Next(5))
                {
                    case 0:
                        Q(1, "workspace.scan", "scanning sector " + _sector.ToString("D4") + "/4096 target=" + Pick(ScanTargets));
                        _sector++; if (_sector > 4096) _sector = 1;
                        break;
                    case 1:
                        Q(1, "queue.worker", "processing queue=" + Pick(Queues) + " item=" + Pick(ItemPrefix) + "-" + _rng.Next(1000, 9999) + " status=RUNNING");
                        break;
                    case 2:
                        Q(0, "visual.pipeline", "frame refreshed frameId=" + _frameId.ToString("D8") + " durationMs=" + _rng.Next(3, 18) + " checksum=" + Hex(4));
                        _frameId++;
                        break;
                    case 3:
                        Q(0, "pipeline.checksum", "block=" + _block.ToString("D8") + " hash=" + Hex(4) + " status=verified");
                        _block++;
                        break;
                    default:
                        Q(0, "input.counter", "suppressedKeyboard=" + _suppressedKb + " suppressedMouse=" + _suppressedMs + " capturedUnlockInput=" + _capturedUnlock);
                        break;
                }
            }
        }

        // ── TerminalPipeline：視覺管線與佇列處理 ──
        private void EnqueuePipeline()
        {
            int n = _rng.Next(2, 5);
            for (int i = 0; i < n; i++)
            {
                switch (_rng.Next(4))
                {
                    case 0:
                        Q(0, "visual.pipeline", "frame refreshed frameId=" + _frameId.ToString("D8") + " durationMs=" + _rng.Next(3, 18) + " checksum=" + Hex(4));
                        _frameId++;
                        break;
                    case 1:
                        Q(1, "queue.worker", "processing queue=" + Pick(Queues) + " item=" + Pick(ItemPrefix) + "-" + _rng.Next(1000, 9999) + " status=" + Pick(new[] { "RUNNING", "DONE", "QUEUED" }));
                        break;
                    case 2:
                        Q(0, "pipeline.checksum", "block=" + _block.ToString("D8") + " hash=" + Hex(4) + " status=verified");
                        _block++;
                        break;
                    default:
                        Q(1, "workspace.scan", "scanning sector " + _sector.ToString("D4") + "/4096 target=" + Pick(ScanTargets));
                        _sector++; if (_sector > 4096) _sector = 1;
                        break;
                }
            }
        }

        // ── InputShield：偵測並攔截使用者鍵鼠輸入 ──
        private void EnqueueInputShield()
        {
            int keys = _rng.Next(2, 6);
            for (int i = 0; i < keys; i++) { Q(2, "input.keyboard", "key=VK_" + Vk() + " action=SUPPRESSED source=physical"); _suppressedKb++; }
            if (_rng.Next(2) == 0) { Q(2, "input.mouse", "dx=" + _rng.Next(-40, 41) + " dy=" + _rng.Next(-40, 41) + " action=SUPPRESSED"); _suppressedMs++; }
            if (_rng.Next(2) == 0) { Q(2, "input.mouse", "button=" + Pick(MouseBtns) + " action=SUPPRESSED"); _suppressedMs++; }
            Q(0, "input.counter", "suppressedKeyboard=" + _suppressedKb + " suppressedMouse=" + _suppressedMs + " capturedUnlockInput=" + _capturedUnlock);
            if (_rng.Next(3) == 0)
            {
                Q(3, "shield.system", "secure attention sequence cannot be intercepted key=CTRL+ALT+DEL");
                Q(0, "shield.system", "fallback policy=ALLOW_SYSTEM_RESERVED_KEYS");
            }
        }

        // ── Unlock：解鎖面板開啟 → 驗證失敗 → 收起（不顯示真實密碼）──
        private void EnqueueUnlock()
        {
            Q(0, "panel.unlock", "unlock panel requested trigger=" + Pick(Triggers));
            Q(0, "panel.unlock", "input focus moved to secure password field");
            Q(2, "input.keyboard", "key=ENTER action=CAPTURED target=unlock-panel");
            _capturedUnlock++;
            Q(0, "auth.session", "password buffer updated length=" + _rng.Next(4, 13) + " masked=true");
            Q(0, "auth.verify", "verifying password challenge session=" + _sessionId.Substring(3));
            _attempts++;
            Q(3, "auth.verify", "unlock attempt failed reason=HASH_MISMATCH attempts=" + _attempts);
            Q(0, "auth.session", "password buffer cleared");
            Q(0, "panel.unlock", "unlock panel hidden reason=FAILED_ATTEMPT");
        }

        // ── OTP：F2 一次性救援碼流程（token / 碼皆遮蔽）──
        private void EnqueueOtp()
        {
            Q(0, "rescue.otp", "rescue request received trigger=F2");
            Q(0, "rescue.otp", "generating one-time unlock code ttl=300s digits=6");
            Q(0, "crypto.random", "secure random source=Windows-CNG provider=BCryptGenRandom");
            Q(0, "rescue.otp", "otp challenge created id=OTP-XXXX expiresAt=" + _base.AddMinutes(5).ToString("HH:mm:ss"));
            Q(0, "notifier.router", "selected channel=telegram fallback=ntfy");
            Q(0, "notifier.telegram", "POST https://api.telegram.org/bot***/sendMessage status=200 durationMs=" + _rng.Next(120, 900));
            Q(0, "rescue.otp", "delivery status=SENT channel=telegram");
            Q(0, "rescue.otp", "waiting for unlock code input");
        }

        // ── Diagnostics：健康檢查 ──
        private void EnqueueDiag()
        {
            Q(0, "diag.health", "keyboardHook=OK mouseHook=OK notifier=READY renderer=READY");
            Q(0, "monitor.heartbeat", "state=GUARDING uptime=" + Uptime() + " cpu=" + Cpu() + "% memory=" + Mem() + "MB");
            if (_rng.Next(2) == 0) { Q(0, "pipeline.checksum", "block=" + _block.ToString("D8") + " hash=" + Hex(4) + " status=verified"); _block++; }
        }

        // ── TerminalPipeline / CyberWatch：裝飾性資料流 ──
        private void EnqueueCyber()
        {
            int n = _rng.Next(2, 5);
            for (int i = 0; i < n; i++) Q(4, "terminal.stream", "0x" + Hex(4) + "  " + HexBytes(_rng.Next(8, 17)));
            if (_rng.Next(2) == 0) { Q(1, "workspace.scan", "scanning sector " + _sector.ToString("D4") + "/4096 target=" + Pick(ScanTargets)); _sector++; }
        }

        // ── Progress：進度條單行 ──
        private void EnqueueProgress()
        {
            int p = Pick(new[] { 24, 38, 46, 57, 71, 88, 100 });
            int filled = p / 5, total = 20;
            string bar = new string('#', filled) + new string('-', total - filled);
            Q(0, "terminal.progress", "[" + bar + "] " + p.ToString().PadLeft(3) + "% " + Pick(ProgressLabels));
        }

        // ── 文字 / 數值小工具 ──
        private static readonly string[] ScanTargets = { "desktop-buffer", "input-shield", "visual-cache", "guard-surface", "overlay-frame" };
        private static readonly string[] Queues = { "visual-refresh", "event-stream", "heartbeat", "checksum", "notifier" };
        private static readonly string[] ItemPrefix = { "VR", "EV", "HB", "CK", "NT" };
        private static readonly string[] MouseBtns = { "LEFT", "RIGHT", "MIDDLE" };
        private static readonly string[] Triggers = { "keyboard", "mouse" };
        private static readonly string[] ProgressLabels = { "stabilizing guard session", "validating input shield", "restoring guard surface", "guard session stabilized" };
        private static readonly string[] OsBuilds = { "10.0.19045", "10.0.22631", "10.0.26100" };

        private string OsVer() { return Pick(OsBuilds); }
        private int Cpu2 { get { return _rng.Next(0, 9); } }
        private string Cpu() { return _rng.Next(1, 6) + "." + Cpu2; }
        private string Mem() { return _rng.Next(44, 92).ToString(); }
        private string Vk()
        {
            int r = _rng.Next(30);
            if (r < 26) return ((char)('A' + r)).ToString();
            return Pick(new[] { "SHIFT", "SPACE", "TAB", "BACK", "RETURN" });
        }
        private string Pick(string[] a) { return a[_rng.Next(a.Length)]; }
        private int Pick(int[] a) { return a[_rng.Next(a.Length)]; }
        private string Hex(int bytes)
        {
            var sb = new StringBuilder(bytes * 2);
            for (int i = 0; i < bytes; i++) sb.Append(_rng.Next(0, 256).ToString("x2"));
            return sb.ToString();
        }
        private string HexBytes(int n)
        {
            var sb = new StringBuilder(n * 3);
            for (int i = 0; i < n; i++) { if (i > 0) sb.Append(' '); sb.Append(_rng.Next(0, 256).ToString("X2")); }
            return sb.ToString();
        }
        private string TimeStamp() { return "[" + _base.AddMilliseconds(_simMs).ToString("HH:mm:ss.fff") + "]"; }
        private string Uptime()
        {
            int sec = (int)Math.Max(0, (_simMs - _bootDoneMs) / 1000.0);
            return (sec / 3600).ToString("D2") + ":" + ((sec / 60) % 60).ToString("D2") + ":" + (sec % 60).ToString("D2");
        }

        // ── 顏色（依設計文件 terminal-guard 配色）──
        private static Color LevelColor(int level)
        {
            switch (level)
            {
                case 1:  return Color.FromArgb(235, 154, 184, 255);  // DATA  藍
                case 2:  return Color.FromArgb(238, 255, 188, 140);  // EVENT 橙
                case 3:  return Color.FromArgb(238, 255, 211, 110);  // WARN  黃
                case 4:  return Color.FromArgb(225, 182, 161, 255);  // TRACE 紫
                case 5:  return Color.FromArgb(240, 255, 122, 122);  // ERROR 紅
                default: return Color.FromArgb(238, 125, 255, 174);  // INFO  綠
            }
        }
        private static readonly string[] LevelText = { "INFO ", "DATA ", "EVENT", "WARN ", "TRACE", "ERROR" };
        private static readonly Color TimeColor = Color.FromArgb(200, 110, 150, 130);   // 時間戳 暗綠灰
        private static readonly Color NsColor   = Color.FromArgb(225, 130, 195, 235);   // namespace 青
        private static readonly Color MsgColor  = Color.FromArgb(235, 217, 247, 230);   // 一般訊息 淡綠白

        private static GraphicsPath RoundedRect(Rectangle r, int rad)
        {
            var p = new GraphicsPath();
            int d = rad * 2;
            if (d <= 0 || d > r.Width || d > r.Height) { p.AddRectangle(r); return p; }
            p.AddArc(r.Left, r.Top, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Top, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.Left, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }
        private static GraphicsPath RoundedRectTop(Rectangle r, int rad)
        {
            var p = new GraphicsPath();
            int d = rad * 2;
            p.AddArc(r.Left, r.Top, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Top, d, d, 270, 90);
            p.AddLine(r.Right, r.Top + rad, r.Right, r.Bottom);
            p.AddLine(r.Right, r.Bottom, r.Left, r.Bottom);
            p.CloseFigure();
            return p;
        }
        private static void DrawDot(Graphics g, int x, int y, int dia, Color c)
        {
            using (var b = new SolidBrush(c)) g.FillEllipse(b, x, y, dia, dia);
        }

        public void Render(Graphics g, Rectangle area, float scale)
        {
            int fontPx = Math.Max(14, (int)(16 * scale));
            int lineH = (int)(fontPx * 1.3);
            int pad = (int)(14 * scale);
            int titleH = Math.Max(22, (int)(28 * scale));
            int radius = Math.Max(6, (int)(10 * scale));

            var prevSmooth = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var path = RoundedRect(area, radius))
            using (var body = new SolidBrush(Color.FromArgb(220, 6, 18, 13)))      // 深綠終端底（半透）
            using (var border = new Pen(Color.FromArgb(185, 60, 120, 95), Math.Max(1f, scale)))
            {
                g.FillPath(body, path);
                g.DrawPath(border, path);
            }
            var titleRect = new Rectangle(area.Left, area.Top, area.Width, titleH);
            using (var tpath = RoundedRectTop(titleRect, radius))
            using (var tbg = new LinearGradientBrush(titleRect, Color.FromArgb(240, 28, 56, 46), Color.FromArgb(240, 16, 34, 28), LinearGradientMode.Vertical))
                g.FillPath(tbg, tpath);

            int dia = Math.Max(8, (int)(12 * scale));
            int dy = area.Top + (titleH - dia) / 2;
            int dx = area.Left + (int)(16 * scale);
            int gap = dia + (int)(8 * scale);
            DrawDot(g, dx, dy, dia, Color.FromArgb(255, 95, 86));
            DrawDot(g, dx + gap, dy, dia, Color.FromArgb(255, 189, 46));
            DrawDot(g, dx + gap * 2, dy, dia, Color.FromArgb(39, 201, 63));
            g.SmoothingMode = prevSmooth;

            var content = new Rectangle(area.Left, area.Top + titleH, area.Width, area.Height - titleH);
            int vis = Math.Max(1, (content.Height - pad * 2) / lineH);
            int start = Math.Max(0, _lines.Count - vis);

            using (var tFont = new Font("Segoe UI Semibold", Math.Max(9f, 10f * scale), FontStyle.Regular, GraphicsUnit.Point))
            using (var tBrush = new SolidBrush(Color.FromArgb(230, 200, 230, 212)))
            using (var tFmt = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                g.DrawString("StillGuard — guard — " + _cols + "×" + vis, tFont, tBrush, new RectangleF(area.Left, area.Top, area.Width, titleH), tFmt);

            var savedClip = g.Clip;
            g.IntersectClip(content);
            using (var font = new Font("Consolas", fontPx, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var fmt = new StringFormat(StringFormatFlags.NoWrap))
            using (var bTime = new SolidBrush(TimeColor))
            using (var bNs = new SolidBrush(NsColor))
            using (var bMsg = new SolidBrush(MsgColor))
            {
                float cw = g.MeasureString("MMMMMMMMMM", font, int.MaxValue, fmt).Width / 10f;   // 等寬字元寬
                float x0 = content.Left + pad;
                int y = content.Top + pad;
                for (int i = start; i < _lines.Count; i++)
                {
                    var ln = _lines[i];
                    using (var bLvl = new SolidBrush(LevelColor(ln.Level)))
                    {
                        float x = x0;
                        g.DrawString(ln.Time, font, bTime, x, y, fmt);
                        x += cw * 15;                                  // 時間欄 [HH:MM:SS.fff]
                        g.DrawString(LevelText[ln.Level % 6], font, bLvl, x, y, fmt);
                        x += cw * 6;                                   // 等級欄
                        g.DrawString((ln.Ns ?? "").PadRight(22), font, bNs, x, y, fmt);
                        x += cw * 24;                                  // namespace 欄
                        g.DrawString(ln.Msg ?? "", font, (ln.Level >= 2 ? bLvl : bMsg), x, y, fmt);
                    }
                    y += lineH;
                }
                if (_frame % 8 < 5)   // 閃爍游標（接在最後一行尾端）
                {
                    using (var bCur = new SolidBrush(LevelColor(0)))
                        g.DrawString("_", font, bCur, x0, y, fmt);
                }
            }
            g.Clip = savedClip;
        }
    }

    // =========================================================================
    //  偽 Windows 更新畫面（障眼模式）
    //  純黑底 + Windows 11 風格單圈旋轉弧 + 中文「正在處理更新…請勿關閉電腦」，
    //  百分比緩慢爬升、偶爾卡住，營造系統更新中的錯覺。純裝飾，不影響安全。
    // =========================================================================
    internal sealed class WindowsUpdateScene
    {
        private readonly Random _rng = new Random();
        private float _t;         // spinner 全域時間相位（0~1 循環）
        private int _pct;         // 目前階段的已完成百分比
        private int _stage;       // 更新階段索引（循環，永遠在忙，不會顯示成「完成」）
        private int _wait;        // 距下次 +1% 的剩餘 tick（製造緩慢與卡頓）
        public string Lang = "zh";   // 文字語言：zh（中文）| en（英文）

        // 多階段標題（仿真實 Windows 更新：下載 → 處理 → 設定 → 即將完成，各階段各自 0~100%）
        private static readonly string[] StagesZh = { "正在下載更新", "正在處理更新", "正在設定更新", "即將完成" };
        private static readonly string[] StagesEn = { "Downloading updates", "Working on updates", "Configuring update for Windows", "Almost done" };

        private const float CycleSec = 1.6f;   // 圓點繞行一圈的週期（秒）
        private const int DotCount = 5;        // 追逐圓點數量（仿 Windows boot throbber）

        // 由動畫計時器（約 32ms）驅動：spinner 圓點追逐，百分比慢爬偶爾停頓
        public void Step()
        {
            _t += 0.032f / CycleSec;
            if (_t >= 1f) _t -= 1f;

            if (_wait > 0) { _wait--; return; }
            if (_pct >= 100)
            {
                // 到 100% → 進入下一個更新階段（標題改變、百分比歸零），永遠在忙不會「完成」
                _pct = 0;
                _stage = (_stage + 1) % StagesZh.Length;
                _wait = _rng.Next(60, 120);                       // 階段間短暫停頓
                return;
            }

            _pct++;
            _wait = _rng.Next(20, 55);                            // 每 1% 約 0.6~1.8 秒
            if (_rng.Next(10) == 0) _wait += _rng.Next(40, 120);  // 偶爾卡住（像在等待）
        }

        // 平滑緩動（頭尾慢、中段快）→ 圓點繞行時聚散加速，貼近 Windows throbber 觀感
        private static float EaseInOutCubic(float x)
        {
            if (x < 0.5f) return 4f * x * x * x;
            float u = -2f * x + 2f;
            return 1f - (u * u * u) / 2f;
        }

        // 在指定區域（通常為主螢幕）置中繪製整個假更新畫面
        public void Render(Graphics g, Rectangle area, float scale)
        {
            int cx = area.Left + area.Width / 2;
            int cy = area.Top + (int)(area.Height * 0.40);
            int R = Math.Max(18, (int)(area.Height * 0.05));

            var prevSmooth = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            // 仿 Windows boot throbber：N 顆白點沿圓周追逐，靠緩動造成聚散加速感
            float dotR = Math.Max(2f, R * 0.085f);
            using (var dot = new SolidBrush(Color.FromArgb(245, 255, 255, 255)))
            {
                for (int i = 0; i < DotCount; i++)
                {
                    float lt = _t - i * 0.06f;          // 各點時間錯開 → 形成彗星狀群聚
                    lt -= (float)Math.Floor(lt);        // 取小數，落在 0~1
                    float e = EaseInOutCubic(lt);
                    double ang = (-90.0 + 360.0 * e) * Math.PI / 180.0;   // 由正上方起算
                    float px = cx + (float)(R * Math.Cos(ang));
                    float py = cy + (float)(R * Math.Sin(ang));
                    g.FillEllipse(dot, px - dotR, py - dotR, dotR * 2, dotR * 2);
                }
            }
            g.SmoothingMode = prevSmooth;

            float mainPx = Math.Max(16f, area.Height * 0.026f);
            float subPx = Math.Max(12f, area.Height * 0.0175f);
            int mainY = cy + R + (int)(area.Height * 0.05);

            bool en = (Lang ?? "zh").Trim().ToLowerInvariant() == "en";
            string family = en ? "Segoe UI" : "Microsoft JhengHei UI";
            int st = _stage % StagesZh.Length;
            string mainText = en ? (StagesEn[st] + "  " + _pct + "% complete")
                                 : (StagesZh[st] + "  " + _pct + "% 完成");
            string subText = en ? "Don't turn off your computer." : "請勿關閉電腦。";

            using (var fMain = new Font(family, mainPx, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var fSub = new Font(family, subPx, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var wBrush = new SolidBrush(Color.FromArgb(245, 245, 245, 245)))
            using (var sBrush = new SolidBrush(Color.FromArgb(210, 215, 215, 215)))
            using (var fmt = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Near })
            {
                var mainRect = new RectangleF(area.Left, mainY, area.Width, mainPx * 1.6f);
                g.DrawString(mainText, fMain, wBrush, mainRect, fmt);
                var subRect = new RectangleF(area.Left, mainY + mainPx * 1.9f, area.Width, subPx * 1.6f);
                g.DrawString(subText, fSub, sBrush, subRect, fmt);
            }
        }
    }

    // =========================================================================
    //  背景層（第 5 節）
    // =========================================================================
    internal static class BackgroundFactory
    {
        public static Bitmap Build(BackgroundConfig cfg, Rectangle virtualScreen)
        {
            switch ((cfg.type ?? "").ToLowerInvariant())
            {
                case "image": return BuildImage(cfg, virtualScreen);
                case "soliddark": return BuildSolid(virtualScreen);
                case "blurdesktop":
                default: return BuildBlurDesktop(cfg, virtualScreen);
            }
        }

        private static Bitmap BuildSolid(Rectangle vs)
        {
            var bmp = new Bitmap(vs.Width, vs.Height, PixelFormat.Format32bppPArgb);
            using (var g = Graphics.FromImage(bmp))
                g.Clear(Color.FromArgb(18, 18, 20));
            return bmp;
        }

        private static Bitmap BuildImage(BackgroundConfig cfg, Rectangle vs)
        {
            try
            {
                if (string.IsNullOrEmpty(cfg.path) || !File.Exists(cfg.path)) return BuildSolid(vs);
                var bmp = new Bitmap(vs.Width, vs.Height, PixelFormat.Format32bppPArgb);
                using (var src = new Bitmap(cfg.path))
                using (var g = Graphics.FromImage(bmp))
                {
                    g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                    // 等比填滿（cover）
                    double sx = (double)vs.Width / src.Width;
                    double sy = (double)vs.Height / src.Height;
                    double s = Math.Max(sx, sy);
                    int w = (int)(src.Width * s), h = (int)(src.Height * s);
                    int x = (vs.Width - w) / 2, y = (vs.Height - h) / 2;
                    g.DrawImage(src, x, y, w, h);
                }
                if (cfg.blur > 0) ImageBlur.GaussianApprox(bmp, cfg.blur);
                ApplyDim(bmp, cfg.dim);
                return bmp;
            }
            catch { return BuildSolid(vs); }
        }

        // blurDesktop：擷取桌面 → 縮小 → 模糊 → 放大繪製 + 輕微變暗（第 5 節）
        private static Bitmap BuildBlurDesktop(BackgroundConfig cfg, Rectangle vs)
        {
            try
            {
                using (var shot = new Bitmap(vs.Width, vs.Height, PixelFormat.Format32bppPArgb))
                {
                    using (var g = Graphics.FromImage(shot))
                        g.CopyFromScreen(vs.Left, vs.Top, 0, 0, new Size(vs.Width, vs.Height), CopyPixelOperation.SourceCopy);

                    // 縮至約 1/4（比 1/8 保留更多細節，模糊後仍看得出桌面輪廓）
                    int sw = Math.Max(1, vs.Width / 4);
                    int sh = Math.Max(1, vs.Height / 4);
                    using (var small = new Bitmap(sw, sh, PixelFormat.Format32bppPArgb))
                    {
                        using (var g = Graphics.FromImage(small))
                        {
                            g.InterpolationMode = InterpolationMode.HighQualityBilinear;
                            g.DrawImage(shot, 0, 0, sw, sh);
                        }
                        // 在小圖上模糊（半徑依設定縮放；小圖已是 1/4，故半徑收斂）
                        int r = Math.Max(1, cfg.blur / 6);
                        ImageBlur.GaussianApprox(small, r);

                        // 放大回原尺寸（雙線性）
                        var result = new Bitmap(vs.Width, vs.Height, PixelFormat.Format32bppPArgb);
                        using (var g = Graphics.FromImage(result))
                        {
                            g.InterpolationMode = InterpolationMode.HighQualityBilinear;
                            g.DrawImage(small, 0, 0, vs.Width, vs.Height);
                        }
                        ApplyDim(result, cfg.dim);
                        return result;
                    }
                }
            }
            catch { return BuildSolid(vs); }
        }

        private static void ApplyDim(Bitmap bmp, double dim)
        {
            if (dim <= 0) return;
            if (dim > 1) dim = 1;
            using (var g = Graphics.FromImage(bmp))
            using (var brush = new SolidBrush(Color.FromArgb((int)(dim * 255), 0, 0, 0)))
                g.FillRectangle(brush, 0, 0, bmp.Width, bmp.Height);
        }
    }

    // 三通道箱型模糊多趟近似高斯（第 5 節模糊備註）。在縮圖上運算，效能足夠。
    internal static class ImageBlur
    {
        public static void GaussianApprox(Bitmap bmp, int radius)
        {
            if (radius < 1) return;
            // 兩趟箱型模糊近似高斯（趟數越多越糊，兩趟在「保留輪廓」與「防偷看」間較平衡）
            BoxBlur(bmp, radius);
            BoxBlur(bmp, radius);
        }

        private static void BoxBlur(Bitmap bmp, int radius)
        {
            int w = bmp.Width, h = bmp.Height;
            var rect = new Rectangle(0, 0, w, h);
            var data = bmp.LockBits(rect, ImageLockMode.ReadWrite, PixelFormat.Format32bppArgb);
            int stride = data.Stride;
            int bytes = stride * h;
            byte[] src = new byte[bytes];
            byte[] dst = new byte[bytes];
            Marshal.Copy(data.Scan0, src, 0, bytes);

            // 水平
            HorizontalBlur(src, dst, w, h, stride, radius);
            // 垂直（dst→src 重用）
            VerticalBlur(dst, src, w, h, stride, radius);

            Marshal.Copy(src, 0, data.Scan0, bytes);
            bmp.UnlockBits(data);
        }

        private static void HorizontalBlur(byte[] src, byte[] dst, int w, int h, int stride, int r)
        {
            int div = r * 2 + 1;
            for (int y = 0; y < h; y++)
            {
                int row = y * stride;
                int sumB = 0, sumG = 0, sumR = 0, sumA = 0;
                for (int x = -r; x <= r; x++)
                {
                    int cx = Clamp(x, 0, w - 1) * 4 + row;
                    sumB += src[cx]; sumG += src[cx + 1]; sumR += src[cx + 2]; sumA += src[cx + 3];
                }
                for (int x = 0; x < w; x++)
                {
                    int o = row + x * 4;
                    dst[o] = (byte)(sumB / div); dst[o + 1] = (byte)(sumG / div);
                    dst[o + 2] = (byte)(sumR / div); dst[o + 3] = (byte)(sumA / div);
                    int add = Clamp(x + r + 1, 0, w - 1) * 4 + row;
                    int sub = Clamp(x - r, 0, w - 1) * 4 + row;
                    sumB += src[add] - src[sub]; sumG += src[add + 1] - src[sub + 1];
                    sumR += src[add + 2] - src[sub + 2]; sumA += src[add + 3] - src[sub + 3];
                }
            }
        }

        private static void VerticalBlur(byte[] src, byte[] dst, int w, int h, int stride, int r)
        {
            int div = r * 2 + 1;
            for (int x = 0; x < w; x++)
            {
                int col = x * 4;
                int sumB = 0, sumG = 0, sumR = 0, sumA = 0;
                for (int y = -r; y <= r; y++)
                {
                    int cy = Clamp(y, 0, h - 1) * stride + col;
                    sumB += src[cy]; sumG += src[cy + 1]; sumR += src[cy + 2]; sumA += src[cy + 3];
                }
                for (int y = 0; y < h; y++)
                {
                    int o = y * stride + col;
                    dst[o] = (byte)(sumB / div); dst[o + 1] = (byte)(sumG / div);
                    dst[o + 2] = (byte)(sumR / div); dst[o + 3] = (byte)(sumA / div);
                    int add = Clamp(y + r + 1, 0, h - 1) * stride + col;
                    int sub = Clamp(y - r, 0, h - 1) * stride + col;
                    sumB += src[add] - src[sub]; sumG += src[add + 1] - src[sub + 1];
                    sumR += src[add + 2] - src[sub + 2]; sumA += src[add + 3] - src[sub + 3];
                }
            }
        }

        private static int Clamp(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }
    }

    // =========================================================================
    //  主表單：雙態介面 + 低階鉤子（第 3、4 節）
    // =========================================================================
    internal sealed class LockForm : Form
    {
        private enum UiState { Idle, Input }

        private readonly AppConfig _cfg;
        private readonly Rectangle _virtualScreen;
        private readonly Rectangle _primaryLocal;   // 主螢幕區域（表單座標）
        private Bitmap _background;

        private UiState _state = UiState.Idle;
        private readonly StringBuilder _input = new StringBuilder();
        private bool _showError;

        private DateTime _lastActivity = DateTime.Now;
        private string _lastMinute = "";
        private readonly System.Windows.Forms.Timer _tick = new System.Windows.Forms.Timer();

        // 終端特效（依設定挑選風格：駭客 / 仿真守護）
        private ITerminalEffect _terminal;
        private readonly WindowsUpdateScene _update = new WindowsUpdateScene();   // 偽 Windows 更新畫面
        private readonly System.Windows.Forms.Timer _animTimer = new System.Windows.Forms.Timer();

        // OTP 一次性救援碼
        private readonly OtpState _otp = new OtpState();
        private string _otpHint = "";                 // 鎖屏底部的 OTP 狀態提示
        private DateTime _otpLastSent = DateTime.MinValue;

        // Telegram 遠端解鎖輪詢（手機送「/unlock <碼>」即解鎖）
        private Thread _tgListener;
        private volatile bool _listening;
        private long _tgOffset;

        // 鉤子
        private IntPtr _kbHook = IntPtr.Zero;
        private IntPtr _msHook = IntPtr.Zero;
        private NativeMethods.LowLevelProc _kbProc;   // 保持參考避免 GC 回收
        private NativeMethods.LowLevelProc _msProc;

        // 手動追蹤的鍵盤狀態（供 ToUnicode 用）
        private readonly byte[] _keyState = new byte[256];

        public LockForm(AppConfig cfg)
        {
            _cfg = cfg;
            _terminal = TerminalFactory.Create(cfg.terminalStyle);
            _virtualScreen = SystemInformation.VirtualScreen;

            var pb = Screen.PrimaryScreen.Bounds;
            _primaryLocal = new Rectangle(pb.Left - _virtualScreen.Left, pb.Top - _virtualScreen.Top, pb.Width, pb.Height);

            // 表單樣式：無邊框、最上層、覆蓋整個虛擬螢幕
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            TopMost = true;
            StartPosition = FormStartPosition.Manual;
            Bounds = _virtualScreen;
            BackColor = Color.Black;
            DoubleBuffered = true;
            Cursor = Cursors.Default;

            Load += OnLoad;
            FormClosed += OnClosed;
            Paint += OnPaint;

            _tick.Interval = 250;   // 時鐘更新與逾時檢查
            _tick.Tick += OnTick;
        }

        private void OnLoad(object sender, EventArgs e)
        {
            // 背景需在表單顯示「之前」截圖才不會把自己拍進去——故在這裡先隱藏再截。
            Opacity = 0;
            _background = BackgroundFactory.Build(_cfg.background, _virtualScreen);
            Opacity = 1;

            Cursor.Hide();
            TopMost = true;
            Activate();

            InstallHooks();
            _tick.Start();
            StartTelegramListener();   // 啟動 Telegram 遠端解鎖輪詢（若已設定）

            // 終端特效需先依寬度設定每行字數
            if (_cfg.showTerminal)
            {
                float sc = PanelScale();
                int fontPx = Math.Max(11, (int)(12 * sc));
                int pad = (int)(14 * sc);
                int cols = (int)((GetTerminalRect().Width - pad * 2) / (fontPx * 0.6));
                _terminal.SetCols(cols);
            }
            _update.Lang = _cfg.fakeUpdateLang;   // 套用偽更新畫面語言
            // 終端特效或偽更新畫面任一啟用 → 啟動動畫計時器
            if (_cfg.showTerminal || _cfg.fakeUpdate)
            {
                _animTimer.Interval = 32;
                _animTimer.Tick += OnAnim;
                _animTimer.Start();
            }
            Invalidate();
        }

        private void OnClosed(object sender, FormClosedEventArgs e)
        {
            _listening = false;   // 停止 Telegram 輪詢（背景緒為 IsBackground，會自行結束）
            _tick.Stop();
            _animTimer.Stop();
            UninstallHooks();
            Cursor.Show();
            if (_background != null) { _background.Dispose(); _background = null; }
        }

        private void OnAnim(object sender, EventArgs e)
        {
            if (_cfg.fakeUpdate) { _update.Step(); Invalidate(GetUpdateRect()); }
            else { _terminal.Step(); Invalidate(GetTerminalRect()); }
        }

        private Rectangle GetTerminalRect()
        {
            var s = _primaryLocal;
            int mx = (int)(s.Width * 0.06), my = (int)(s.Height * 0.06);
            return new Rectangle(s.Left + mx, s.Top + my, s.Width - mx * 2, s.Height - my * 2);
        }

        // 偽更新畫面的重繪範圍：主螢幕中央（涵蓋 spinner 與文字）
        private Rectangle GetUpdateRect()
        {
            var s = _primaryLocal;
            int w = (int)(s.Width * 0.7), h = (int)(s.Height * 0.55);
            return new Rectangle(s.Left + (s.Width - w) / 2, s.Top + (s.Height - h) / 2, w, h);
        }

        private void OnTick(object sender, EventArgs e)
        {
            bool needPaint = false;

            // 輸入態逾時 → 退回閒置態（第 4 節）
            if (_state == UiState.Input)
            {
                double idle = (DateTime.Now - _lastActivity).TotalSeconds;
                if (idle >= _cfg.idleTimeoutSec)
                {
                    _state = UiState.Idle;
                    _input.Clear();
                    _showError = false;
                    needPaint = true;   // 面板要收起
                }
            }

            // 時鐘只顯示到分鐘，分鐘變了才需重畫（避免每秒重繪整個全螢幕背景）
            string nowMinute = DateTime.Now.ToString("HH:mm");
            if (nowMinute != _lastMinute) { _lastMinute = nowMinute; needPaint = true; }

            if (needPaint) Invalidate();
        }

        // ---- 繪製 ----
        private void OnPaint(object sender, PaintEventArgs e)
        {
            var g = e.Graphics;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

            // 偽 Windows 更新畫面：純黑底接管整個畫面，蓋過背景 / 時鐘 / 終端 / 密碼面板。
            // 刻意「不繪製」密碼面板與任何提示，維持障眼純淨；解鎖機制仍全程運作：
            //   ‧ 直接盲打密碼按 Enter 即解鎖（輸入累積與驗證與繪製無關）
            //   ‧ 按 F2 照常寄送 OTP 一次性碼到裝置
            //   ‧ 手機 Telegram /unlock 遠端解鎖照常
            if (_cfg.fakeUpdate)
            {
                g.Clear(Color.Black);
                _update.Render(g, _primaryLocal, PanelScale());
                return;
            }

            if (_background != null) g.DrawImageUnscaled(_background, 0, 0);
            else g.Clear(Color.Black);

            // 駭客終端特效（疊在背景上、時鐘與面板之下）
            if (_cfg.showTerminal) _terminal.Render(g, GetTerminalRect(), PanelScale());

            // 內建時鐘（閒置態與輸入態都顯示）
            if (_cfg.showClock) ClockRenderer.Draw(g, _primaryLocal);

            // 輸入態：密碼面板
            if (_state == UiState.Input) DrawPasswordPanel(g);
        }

        // 面板縮放倍率（以 1080p 為基準，夾在 1.0~3.0 倍）
        private float PanelScale()
        {
            float scale = _primaryLocal.Height / 1080f;
            if (scale < 1f) scale = 1f;
            if (scale > 3f) scale = 3f;
            return scale;
        }

        private Rectangle GetPanelRect()
        {
            var s = _primaryLocal;
            float scale = PanelScale();
            int panelW = Math.Min((int)(560 * scale), s.Width - 80);
            int panelH = (int)(210 * scale);
            int px = s.Left + (s.Width - panelW) / 2;
            int py = s.Top + (int)(s.Height * 0.60);
            return new Rectangle(px, py, panelW, panelH);
        }

        // 只重繪密碼面板區域（含下方 OTP 提示，避免每次按鍵重畫整個全螢幕背景）
        private void InvalidatePanel()
        {
            var r = GetPanelRect();
            r.Inflate(12, 12);
            r.Height += (int)(60 * PanelScale());   // 涵蓋面板下方的 OTP 提示行
            Invalidate(r);
        }

        private void DrawPasswordPanel(Graphics g)
        {
            float scale = PanelScale();
            var panel = GetPanelRect();

            int pad = (int)(28 * scale);
            int corner = (int)(16 * scale);

            using (var back = new SolidBrush(Color.FromArgb(170, 20, 20, 24)))
            using (var path = RoundedRect(panel, corner))
                g.FillPath(back, path);

            using (var titleFont = new Font("Segoe UI", 20 * scale, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var white = new SolidBrush(Color.White))
            using (var fmt = new StringFormat { Alignment = StringAlignment.Center })
                g.DrawString("輸入密碼以解鎖", titleFont, white, panel.Left + panel.Width / 2f, panel.Top + pad * 0.6f, fmt);

            // 遮罩點（● 第 7 節）
            string masked = new string('●', _input.Length);
            int boxH = (int)(64 * scale);
            int boxY = panel.Top + (int)(64 * scale);
            using (var boxFont = new Font("Consolas", 36 * scale, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var white = new SolidBrush(Color.White))
            using (var fmt = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
            {
                var box = new Rectangle(panel.Left + pad, boxY, panel.Width - pad * 2, boxH);
                using (var boxBrush = new SolidBrush(Color.FromArgb(120, 0, 0, 0)))
                using (var bp = RoundedRect(box, (int)(10 * scale)))
                    g.FillPath(boxBrush, bp);
                g.DrawString(masked.Length == 0 ? "" : masked, boxFont, white, box, fmt);
            }

            // 錯誤提示 / 操作提示
            float footY = panel.Bottom - (int)(34 * scale);
            if (_showError)
            {
                using (var errFont = new Font("Segoe UI", 18 * scale, FontStyle.Bold, GraphicsUnit.Pixel))
                using (var red = new SolidBrush(Color.FromArgb(255, 120, 120)))
                using (var fmt = new StringFormat { Alignment = StringAlignment.Center })
                    g.DrawString("密碼錯誤", errFont, red, panel.Left + panel.Width / 2f, footY, fmt);
            }
            else
            {
                using (var tipFont = new Font("Segoe UI", 15 * scale, FontStyle.Regular, GraphicsUnit.Pixel))
                using (var gray = new SolidBrush(Color.FromArgb(180, 200, 200, 200)))
                using (var fmt = new StringFormat { Alignment = StringAlignment.Center })
                    g.DrawString("Enter 確認 · Backspace 刪除 · Esc 清空", tipFont, gray, panel.Left + panel.Width / 2f, footY, fmt);
            }

            // OTP 救援提示（僅在已啟用且設定完成時顯示）
            if (NotifierFactory.IsConfigured(_cfg.otp))
            {
                string line = string.IsNullOrEmpty(_otpHint)
                    ? "忘記密碼？按 F2 將一次性解鎖碼寄到你的裝置"
                    : _otpHint;
                using (var f = new Font("Segoe UI", 13 * scale, FontStyle.Regular, GraphicsUnit.Pixel))
                using (var b = new SolidBrush(Color.FromArgb(200, 150, 200, 255)))
                using (var fmt = new StringFormat { Alignment = StringAlignment.Center })
                    g.DrawString(line, f, b, panel.Left + panel.Width / 2f, panel.Bottom + (int)(10 * scale), fmt);
            }
        }

        private static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            var path = new GraphicsPath();
            int d = radius * 2;
            path.AddArc(r.Left, r.Top, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Top, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.Left, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        // ---- 鉤子安裝 / 卸載 ----
        private void InstallHooks()
        {
            _kbProc = KeyboardProc;
            _msProc = MouseProc;
            using (var proc = System.Diagnostics.Process.GetCurrentProcess())
            using (var mod = proc.MainModule)
            {
                IntPtr hMod = NativeMethods.GetModuleHandle(mod.ModuleName);
                _kbHook = NativeMethods.SetWindowsHookEx(NativeMethods.WH_KEYBOARD_LL, _kbProc, hMod, 0);
                _msHook = NativeMethods.SetWindowsHookEx(NativeMethods.WH_MOUSE_LL, _msProc, hMod, 0);
            }
        }

        private void UninstallHooks()
        {
            if (_kbHook != IntPtr.Zero) { NativeMethods.UnhookWindowsHookEx(_kbHook); _kbHook = IntPtr.Zero; }
            if (_msHook != IntPtr.Zero) { NativeMethods.UnhookWindowsHookEx(_msHook); _msHook = IntPtr.Zero; }
        }

        // ---- 鍵盤鉤子：吞掉所有事件，於此組密碼字串（第 7 節）----
        private IntPtr KeyboardProc(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                int msg = wParam.ToInt32();
                var data = (NativeMethods.KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(NativeMethods.KBDLLHOOKSTRUCT));
                int vk = (int)data.vkCode;

                bool isDown = (msg == NativeMethods.WM_KEYDOWN || msg == NativeMethods.WM_SYSKEYDOWN);
                bool isUp = (msg == NativeMethods.WM_KEYUP || msg == NativeMethods.WM_SYSKEYUP);

                UpdateModifierState(vk, isDown, isUp);

                if (isDown)
                {
                    // 任意鍵喚醒 → 切換至輸入態
                    bool wasInput = (_state == UiState.Input);
                    WakeToInput();
                    if (_cfg.showTerminal)
                    {
                        if (!wasInput) _terminal.Signal(TermSignal.PanelOpen, "keyboard");
                        if (vk != 0x0D && vk != 0x71) _terminal.Signal(TermSignal.KeySuppressed, null);  // 略過 Enter / F2
                    }
                    HandleKeyDown(vk, data.scanCode);
                    // 立即重繪密碼面板，讓輸入即時反映（不必等計時器，消除延遲感）
                    InvalidatePanel();
                }
            }
            // 全程吞掉，實體輸入不傳入系統（第 4 節）
            return (IntPtr)1;
        }

        private void UpdateModifierState(int vk, bool isDown, bool isUp)
        {
            const int VK_SHIFT = 0x10, VK_LSHIFT = 0xA0, VK_RSHIFT = 0xA1;
            const int VK_CONTROL = 0x11, VK_MENU = 0x12;
            const int VK_CAPITAL = 0x14;

            byte on = 0x80;
            if (vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT)
                _keyState[VK_SHIFT] = isDown ? on : (byte)0;
            else if (vk == VK_CONTROL)
                _keyState[VK_CONTROL] = isDown ? on : (byte)0;
            else if (vk == VK_MENU)
                _keyState[VK_MENU] = isDown ? on : (byte)0;
            else if (vk == VK_CAPITAL && isDown)
                _keyState[VK_CAPITAL] ^= 0x01;   // 切換 CapsLock 低位
        }

        private void HandleKeyDown(int vk, uint scanCode)
        {
            const int VK_RETURN = 0x0D, VK_BACK = 0x08, VK_ESCAPE = 0x1B, VK_F2 = 0x71;

            // F2：寄送一次性解鎖碼到設定的通道
            if (vk == VK_F2)
            {
                SendOtp();
                return;
            }

            if (vk == VK_RETURN)
            {
                // 主密碼 / 救援碼 / 一次性碼（OTP）任一相符即解鎖
                if (PasswordManager.Verify(_cfg, _input.ToString()) || _otp.Verify(_input.ToString()))
                {
                    Unlock();
                }
                else
                {
                    if (_cfg.showTerminal) _terminal.Signal(TermSignal.VerifyAttempt, _input.Length.ToString());
                    _input.Clear();
                    _showError = true;
                }
                return;
            }
            if (vk == VK_BACK)
            {
                if (_input.Length > 0) _input.Length--;
                _showError = false;
                return;
            }
            if (vk == VK_ESCAPE)
            {
                _input.Clear();
                _showError = false;
                return;
            }

            // 一般可列印字元：以 ToUnicode 組字
            string ch = TranslateToChar(vk, scanCode);
            if (!string.IsNullOrEmpty(ch))
            {
                _input.Append(ch);
                _showError = false;
            }
        }

        private void SendOtp()
        {
            if (_cfg.otp == null || !NotifierFactory.IsConfigured(_cfg.otp))
            {
                _otpHint = "未啟用或未設定 OTP 通道";
                InvalidatePanel();
                return;
            }
            // 頻率限制：30 秒內不重複寄送
            if ((DateTime.Now - _otpLastSent).TotalSeconds < 30)
            {
                _otpHint = "請稍候再重寄（30 秒內限一次）";
                InvalidatePanel();
                return;
            }
            _otpLastSent = DateTime.Now;

            string code = _otp.Generate();
            string msg = "【StillGuard 靜守】一次性解鎖碼：" + code + "（5 分鐘內有效）";
            if (_cfg.otp.channel == "telegram")
                msg += "\n\n可直接回覆「/unlock " + code + "」遠端解鎖本機。";
            _otpHint = "寄送中…";
            InvalidatePanel();

            // 網路 I/O 放背景執行緒，不阻塞鉤子
            var cfgOtp = _cfg.otp;
            var t = new Thread(() =>
            {
                INotifier n = NotifierFactory.Create(cfgOtp);
                string err = "通道建立失敗";
                bool ok = (n != null) && n.Send(msg, out err);
                string hint = ok ? "已寄出，請查看你的裝置（5 分鐘內有效）" : ("寄送失敗：" + (err ?? "未知錯誤"));
                Beep(ok);   // 無畫面情境的聲音回饋
                try { BeginInvoke((MethodInvoker)(() => { _otpHint = hint; InvalidatePanel(); })); } catch { }
            });
            t.IsBackground = true;
            t.Start();
        }

        // ---- Telegram 遠端解鎖：鎖屏期間背景輪詢 getUpdates ----
        // 安全模型：① 僅接受設定的 chat_id 來訊 ② 必須附帶 F2 取得的一次性碼（雙重驗證）
        private void StartTelegramListener()
        {
            var o = _cfg.otp;
            if (o == null || !o.enabled || o.channel != "telegram") return;
            string token = DataProtector.Unprotect(o.telegramToken);
            string chatId = o.telegramChatId;
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(chatId)) return;

            _listening = true;
            _tgListener = new Thread(() => TelegramListenLoop(token, chatId)) { IsBackground = true };
            _tgListener.Start();
        }

        private void TelegramListenLoop(string token, string chatId)
        {
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            var ser = new JavaScriptSerializer();
            bool drain = true;   // 首輪只清空積壓訊息（避免重播鎖屏前的舊指令）

            while (_listening)
            {
                try
                {
                    string url = "https://api.telegram.org/bot" + token + "/getUpdates?timeout=20&offset=" + _tgOffset;
                    string json;
                    using (var wc = new WebClient()) { wc.Encoding = Encoding.UTF8; json = wc.DownloadString(url); }
                    if (!_listening) break;

                    var root = ser.DeserializeObject(json) as Dictionary<string, object>;
                    var arr = (root != null && root.ContainsKey("result")) ? root["result"] as object[] : null;
                    if (arr != null)
                    {
                        foreach (var it in arr)
                        {
                            var upd = it as Dictionary<string, object>;
                            if (upd == null) continue;
                            long uid = Convert.ToInt64(upd["update_id"]);
                            if (uid >= _tgOffset) _tgOffset = uid + 1;   // 標記已讀

                            if (drain) continue;   // 首輪不處理，只推進 offset

                            var m = (upd.ContainsKey("message") ? upd["message"] : null) as Dictionary<string, object>;
                            if (m == null) continue;
                            var chat = (m.ContainsKey("chat") ? m["chat"] : null) as Dictionary<string, object>;
                            string fromId = (chat != null && chat.ContainsKey("id")) ? Convert.ToString(chat["id"]) : "";
                            string text = m.ContainsKey("text") ? Convert.ToString(m["text"]) : "";
                            if (fromId != chatId) continue;   // 僅接受設定的 chat_id
                            if (TryRemoteUnlock(text)) return;
                        }
                    }
                    drain = false;
                }
                catch { Thread.Sleep(3000); }   // 連線失敗，稍候重試
            }
        }

        // 解析「/unlock <碼>」（容忍 /unlock@botname），碼須通過一次性驗證
        private bool TryRemoteUnlock(string text)
        {
            if (string.IsNullOrEmpty(text)) return false;
            var parts = text.Trim().Split(new[] { ' ', '\t', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return false;
            if (!parts[0].StartsWith("/unlock", StringComparison.OrdinalIgnoreCase)) return false;
            if (!_otp.Verify(parts[parts.Length - 1].Trim())) return false;

            _listening = false;
            try { Beep(true); } catch { }
            try { BeginInvoke((MethodInvoker)(() => { _otpHint = "已遠端解鎖"; Unlock(); })); } catch { }
            return true;
        }

        // 無畫面情境的聲音回饋（成功 = 雙高音；失敗 = 單低音）
        private static void Beep(bool ok)
        {
            try { if (ok) { Console.Beep(880, 120); Console.Beep(1320, 160); } else Console.Beep(330, 250); } catch { }
        }

        private string TranslateToChar(int vk, uint scanCode)
        {
            var sb = new StringBuilder(8);
            IntPtr layout = NativeMethods.GetKeyboardLayout(0);
            int rc = NativeMethods.ToUnicodeEx((uint)vk, scanCode, _keyState, sb, sb.Capacity, 0, layout);
            if (rc > 0)
            {
                string s = sb.ToString();
                // 過濾控制字元
                if (s.Length > 0 && !char.IsControl(s[0])) return s;
            }
            return null;
        }

        private void WakeToInput()
        {
            _lastActivity = DateTime.Now;
            if (_state != UiState.Input)
            {
                _state = UiState.Input;
                _input.Clear();
                _showError = false;
            }
        }

        private void Unlock()
        {
            // 解鎖 → 關閉本鎖屏視窗並釋放鉤子（OnClosed 卸載）；返回設定主視窗，不結束整個程式。
            BeginInvoke((MethodInvoker)(() =>
            {
                DialogResult = DialogResult.OK;
                Close();
            }));
        }

        // ---- 滑鼠鉤子：吞掉所有事件，移動 / 點擊用於喚醒 UI（第 4 節）----
        private IntPtr MouseProc(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                int msg = wParam.ToInt32();
                // 移動、點擊、滾輪皆視為喚醒
                if (msg == NativeMethods.WM_MOUSEMOVE ||
                    msg == NativeMethods.WM_LBUTTONDOWN || msg == NativeMethods.WM_RBUTTONDOWN ||
                    msg == NativeMethods.WM_MBUTTONDOWN || msg == NativeMethods.WM_MOUSEWHEEL)
                {
                    _lastActivity = DateTime.Now;
                    bool wasInput = (_state == UiState.Input);
                    if (!wasInput)
                    {
                        // 滑鼠喚醒不清空輸入緩衝（其本就為空），但要切換狀態並重繪
                        _state = UiState.Input;
                        BeginInvoke((MethodInvoker)Invalidate);
                    }
                    if (_cfg.showTerminal)
                    {
                        string md = msg == NativeMethods.WM_MOUSEMOVE ? "move"
                                  : msg == NativeMethods.WM_LBUTTONDOWN ? "LEFT"
                                  : msg == NativeMethods.WM_RBUTTONDOWN ? "RIGHT"
                                  : msg == NativeMethods.WM_MBUTTONDOWN ? "MIDDLE" : "WHEEL";
                        _terminal.Signal(TermSignal.MouseSuppressed, md);
                        if (!wasInput) _terminal.Signal(TermSignal.PanelOpen, "mouse");
                    }
                }
            }
            return (IntPtr)1;   // 吞掉所有滑鼠事件
        }

        // 確保表單一直在最上層（防其他視窗搶焦點）
        protected override void OnDeactivate(EventArgs e)
        {
            base.OnDeactivate(e);
            TopMost = true;
        }
    }

    // =========================================================================
    //  Win32 互操作
    // =========================================================================
    internal static class NativeMethods
    {
        public const int WH_KEYBOARD_LL = 13;
        public const int WH_MOUSE_LL = 14;

        public const int WM_KEYDOWN = 0x0100;
        public const int WM_KEYUP = 0x0101;
        public const int WM_SYSKEYDOWN = 0x0104;
        public const int WM_SYSKEYUP = 0x0105;

        public const int WM_MOUSEMOVE = 0x0200;
        public const int WM_LBUTTONDOWN = 0x0201;
        public const int WM_RBUTTONDOWN = 0x0204;
        public const int WM_MBUTTONDOWN = 0x0207;
        public const int WM_MOUSEWHEEL = 0x020A;

        public delegate IntPtr LowLevelProc(int nCode, IntPtr wParam, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        public struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetWindowsHookEx(int idHook, LowLevelProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        // 全域熱鍵
        public const int WM_HOTKEY = 0x0312;
        public const uint MOD_ALT = 0x0001, MOD_CONTROL = 0x0002, MOD_SHIFT = 0x0004, MOD_WIN = 0x0008, MOD_NOREPEAT = 0x4000;

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool UnregisterHotKey(IntPtr hWnd, int id);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        // DPI 感知：讓截圖與座標使用實體像素，修正高 DPI / 多螢幕下截圖只截一部分的問題。
        [DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();

        [DllImport("user32.dll")]
        public static extern bool SetProcessDpiAwarenessContext(IntPtr value);

        // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4（Win10 1703+）
        public static readonly IntPtr DPI_PER_MONITOR_V2 = new IntPtr(-4);

        public static void EnableDpiAwareness()
        {
            // 採 System Aware：足以修正截圖的像素不一致，且 WinForms .NET Framework
            // 對 System DPI 有良好的字體 / 佈局自動縮放（PMv2 在 4.x 反而會讓視窗變小）。
            try { SetProcessDPIAware(); } catch { }
        }

        [DllImport("user32.dll")]
        public static extern IntPtr GetKeyboardLayout(uint idThread);

        [DllImport("user32.dll")]
        public static extern int ToUnicodeEx(uint wVirtKey, uint wScanCode, byte[] lpKeyState,
            [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pwszBuff, int cchBuff, uint wFlags, IntPtr dwhkl);
    }

    // =========================================================================
    //  即時預覽控制項 —— 縮放繪製背景與 widgets，所見即所得（依老爺指示）。
    // =========================================================================
    internal sealed class PreviewPanel : Panel
    {
        private AppConfig _cfg;
        private Bitmap _desktopThumb;        // 主螢幕截圖縮圖（原圖，未模糊）
        private readonly Rectangle _primary;
        private readonly System.Windows.Forms.Timer _clock = new System.Windows.Forms.Timer();
        private readonly System.Windows.Forms.Timer _fastClock = new System.Windows.Forms.Timer();
        private ITerminalEffect _previewTerm;
        private string _previewStyle;
        private readonly WindowsUpdateScene _previewUpdate = new WindowsUpdateScene();

        public PreviewPanel()
        {
            _primary = Screen.PrimaryScreen.Bounds;
            DoubleBuffered = true;
            BackColor = Color.Black;
            CaptureDesktop();
            _clock.Interval = 1000;           // 讓預覽的時鐘也會跳秒（終端在此節奏緩慢示意）
            _clock.Tick += (s, e) => Invalidate();
            _clock.Start();
            // 偽更新畫面的圓點需流暢旋轉：僅在該模式啟用時以 ~31fps 重繪（不重建背景，成本低）
            _fastClock.Interval = 32;
            _fastClock.Tick += (s, e) => { if (_cfg != null && _cfg.fakeUpdate) Invalidate(); };
            _fastClock.Start();
        }

        public void SetConfig(AppConfig cfg) { _cfg = cfg; Invalidate(); }

        private void CaptureDesktop()
        {
            try
            {
                int tw = 640;
                int th = Math.Max(1, (int)(_primary.Height * (640.0 / _primary.Width)));
                var thumb = new Bitmap(tw, th, PixelFormat.Format32bppPArgb);
                using (var full = new Bitmap(_primary.Width, _primary.Height, PixelFormat.Format32bppPArgb))
                {
                    using (var g = Graphics.FromImage(full))
                        g.CopyFromScreen(_primary.Left, _primary.Top, 0, 0, _primary.Size, CopyPixelOperation.SourceCopy);
                    using (var g = Graphics.FromImage(thumb))
                    {
                        g.InterpolationMode = InterpolationMode.HighQualityBilinear;
                        g.DrawImage(full, 0, 0, tw, th);
                    }
                }
                if (_desktopThumb != null) _desktopThumb.Dispose();
                _desktopThumb = thumb;
            }
            catch { }
        }

        // 重新擷取桌面（鎖定前後桌面可能有變化時用）
        public void RefreshDesktop() { CaptureDesktop(); Invalidate(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Color.Black);
            if (_cfg == null) return;

            // 維持主螢幕比例，置中（letterbox）
            var area = ClientRectangle;
            double scale = Math.Min((double)area.Width / _primary.Width, (double)area.Height / _primary.Height);
            int dw = (int)(_primary.Width * scale), dh = (int)(_primary.Height * scale);
            int dx = area.Left + (area.Width - dw) / 2, dy = area.Top + (area.Height - dh) / 2;
            var dest = new Rectangle(dx, dy, dw, dh);

            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

            // 偽 Windows 更新畫面：純黑底接管預覽，蓋過背景 / 時鐘 / 終端
            if (_cfg.fakeUpdate)
            {
                using (var black = new SolidBrush(Color.Black)) g.FillRectangle(black, dest);
                float usc = (float)((double)dh / _primary.Height);
                _previewUpdate.Lang = _cfg.fakeUpdateLang;
                _previewUpdate.Step();
                _previewUpdate.Render(g, dest, usc);
                return;
            }

            // 背景
            using (var bg = BuildPreviewBackground(dw, dh))
                if (bg != null) g.DrawImage(bg, dest);

            // 駭客終端特效（疊在背景上、時鐘之下；預覽以 1 秒節奏緩慢滾動示意）
            if (_cfg.showTerminal)
            {
                string style = string.IsNullOrEmpty(_cfg.terminalStyle) ? "hacker" : _cfg.terminalStyle;
                if (_previewTerm == null || _previewStyle != style)
                { _previewTerm = TerminalFactory.Create(style); _previewStyle = style; }

                int mx = (int)(dw * 0.06), my = (int)(dh * 0.06);
                var trect = new Rectangle(dx + mx, dy + my, dw - mx * 2, dh - my * 2);
                float tsc = (float)((double)dh / _primary.Height);
                int fpx = Math.Max(11, (int)(12 * tsc)), tpad = (int)(14 * tsc);
                _previewTerm.SetCols((int)((trect.Width - tpad * 2) / (fpx * 0.6)));
                _previewTerm.Step();
                _previewTerm.Render(g, trect, tsc);
            }

            // 內建時鐘（用縮放座標，使字級/位置與實機一致）
            if (_cfg.showClock)
            {
                var state = g.Save();
                g.TranslateTransform(dx, dy);
                g.ScaleTransform((float)scale, (float)scale);
                ClockRenderer.Draw(g, new Rectangle(0, 0, _primary.Width, _primary.Height));
                g.Restore(state);
            }

            // 邊框
            using (var pen = new Pen(Color.FromArgb(80, 255, 255, 255)))
                g.DrawRectangle(pen, dest.Left, dest.Top, dest.Width - 1, dest.Height - 1);
        }

        private Bitmap BuildPreviewBackground(int w, int h)
        {
            if (w < 1 || h < 1) return null;
            var bg = _cfg.background;
            var bmp = new Bitmap(w, h, PixelFormat.Format32bppPArgb);
            using (var g = Graphics.FromImage(bmp))
            {
                g.InterpolationMode = InterpolationMode.HighQualityBilinear;
                switch ((bg.type ?? "").ToLowerInvariant())
                {
                    case "soliddark":
                        g.Clear(Color.FromArgb(18, 18, 20));
                        break;
                    case "image":
                        try
                        {
                            if (!string.IsNullOrEmpty(bg.path) && File.Exists(bg.path))
                                using (var src = new Bitmap(bg.path))
                                {
                                    double s = Math.Max((double)w / src.Width, (double)h / src.Height);
                                    int iw = (int)(src.Width * s), ih = (int)(src.Height * s);
                                    g.DrawImage(src, (w - iw) / 2, (h - ih) / 2, iw, ih);
                                }
                            else g.Clear(Color.FromArgb(18, 18, 20));
                        }
                        catch { g.Clear(Color.FromArgb(18, 18, 20)); }
                        break;
                    case "blurdesktop":
                    default:
                        if (_desktopThumb != null) g.DrawImage(_desktopThumb, 0, 0, w, h);
                        else g.Clear(Color.FromArgb(18, 18, 20));
                        break;
                }
            }

            string type = (bg.type ?? "").ToLowerInvariant();
            if ((type == "blurdesktop" || type == "image") && bg.blur > 0)
            {
                // 預覽尺寸已小，半徑相應縮放
                int r = Math.Max(1, (int)Math.Round(bg.blur * (w / (double)_primary.Width) * 1.5));
                ImageBlur.GaussianApprox(bmp, r);
            }
            if (type != "soliddark") ApplyDimPreview(bmp, bg.dim);
            return bmp;
        }

        private static void ApplyDimPreview(Bitmap bmp, double dim)
        {
            if (dim <= 0) return; if (dim > 1) dim = 1;
            using (var g = Graphics.FromImage(bmp))
            using (var b = new SolidBrush(Color.FromArgb((int)(dim * 255), 0, 0, 0)))
                g.FillRectangle(b, 0, 0, bmp.Width, bmp.Height);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { _clock.Dispose(); _fastClock.Dispose(); if (_desktopThumb != null) _desktopThumb.Dispose(); }
            base.Dispose(disposing);
        }
    }

    // =========================================================================
    //  設定主視窗（依老爺指示：主視窗即設定面板，關閉縮到系統匣）
    // =========================================================================
    internal sealed class SettingsForm : Form
    {
        private readonly string _cfgPath;
        private AppConfig _cfg;

        private ComboBox _bgType;
        private NumericUpDown _blur, _dim, _idle;
        private TextBox _imagePath;
        private Button _browseImage;
        private CheckBox _showClock;
        private CheckBox _showTerminal;
        private ComboBox _termStyle;
        private CheckBox _fakeUpdate;
        private ComboBox _fakeUpdateLang;
        private PreviewPanel _preview;
        private TextBox _pw1, _pw2;
        private TextBox _rescue1, _rescue2;
        private Label _pwStatus;
        private Label _rescueStatus;
        private CheckBox _otpEnabled;
        private ComboBox _otpChannel;
        private TextBox _tgToken, _tgChatId, _dcWebhook, _ntfyServer, _ntfyTopic;
        private Label _otpStatus;
        private NotifyIcon _tray;
        private TextBox _hotkeyBox;
        private Label _hotkeyStatus;
        private bool _reallyExit;
        private bool _binding;                                    // 載入設定到畫面期間，抑制控制項事件回寫
        private bool _hotkeyRecording;                            // 快捷鍵錄製模式
        private bool _isLocking;                                   // 防止鎖定中重入（熱鍵連按 / 按鈕）
        private bool _hotkeyRegistered;
        private const int HOTKEY_ID = 0xA11C;
        private DateTime _lockCooldownUntil = DateTime.MinValue;   // 解鎖後忽略鎖定請求的期間

        public SettingsForm(string cfgPath)
        {
            _cfgPath = cfgPath;
            _cfg = AppConfig.LoadOrDefault(cfgPath);

            Text = "StillGuard 靜守 — 設定";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(940, 620);
            MinimumSize = new Size(900, 600);
            Font = new Font("Segoe UI", 9f);
            try { Icon = AppIcon.Load(); } catch { }

            BuildUi();
            BindFromConfig();

            FormClosing += OnFormClosing;
            BuildTray();
        }

        // ---- 介面建構 ----
        private void BuildUi()
        {
            // 左：設定欄；右：即時預覽
            var split = new SplitContainer
            {
                Dock = DockStyle.Fill,
                Orientation = Orientation.Vertical,
                FixedPanel = FixedPanel.Panel2
            };
            Controls.Add(split);
            try { split.SplitterDistance = 460; } catch { }

            // ===== 左側設定 =====
            var left = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(12), AutoScroll = true };
            split.Panel1.Controls.Add(left);

            left.Controls.Add(SectionLabel("背景"));

            var bgPanel = new TableLayoutPanel { ColumnCount = 4, AutoSize = true, Dock = DockStyle.Top };
            bgPanel.Controls.Add(new Label { Text = "類型", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 0);
            _bgType = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 140 };
            _bgType.Items.AddRange(new object[] { "blurDesktop", "image", "solidDark" });
            _bgType.SelectedIndexChanged += (s, e) => { Pull(); UpdatePreview(); };
            bgPanel.Controls.Add(_bgType, 1, 0);

            bgPanel.Controls.Add(new Label { Text = "模糊", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(12, 7, 3, 3) }, 2, 0);
            _blur = new NumericUpDown { Minimum = 0, Maximum = 60, Width = 70 };
            _blur.ValueChanged += (s, e) => { Pull(); UpdatePreview(); };
            bgPanel.Controls.Add(_blur, 3, 0);

            bgPanel.Controls.Add(new Label { Text = "變暗 %", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 1);
            _dim = new NumericUpDown { Minimum = 0, Maximum = 100, Width = 70 };
            _dim.ValueChanged += (s, e) => { Pull(); UpdatePreview(); };
            bgPanel.Controls.Add(_dim, 1, 1);
            left.Controls.Add(bgPanel);

            var imgPanel = new TableLayoutPanel { ColumnCount = 3, AutoSize = true, Dock = DockStyle.Top };
            imgPanel.Controls.Add(new Label { Text = "圖片", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 0);
            _imagePath = new TextBox { Width = 280 };
            _imagePath.TextChanged += (s, e) => { Pull(); UpdatePreview(); };
            imgPanel.Controls.Add(_imagePath, 1, 0);
            _browseImage = new Button { Text = "瀏覽…", AutoSize = true };
            _browseImage.Click += BrowseImage;
            imgPanel.Controls.Add(_browseImage, 2, 0);
            left.Controls.Add(imgPanel);

            left.Controls.Add(SectionLabel("行為"));
            var behav = new TableLayoutPanel { ColumnCount = 3, AutoSize = true, Dock = DockStyle.Top };
            behav.Controls.Add(new Label { Text = "輸入逾時（秒）", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 0);
            _idle = new NumericUpDown { Minimum = 3, Maximum = 120, Width = 70 };
            _idle.ValueChanged += (s, e) => Pull();
            behav.Controls.Add(_idle, 1, 0);

            behav.Controls.Add(new Label { Text = "鎖定快捷鍵", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 1);
            _hotkeyBox = new TextBox { Width = 160, ReadOnly = true, Cursor = Cursors.Hand };
            _hotkeyBox.KeyDown += HotkeyBox_KeyDown;
            _hotkeyBox.Click += (s, e) => BeginHotkeyRecord();
            _hotkeyBox.Leave += (s, e) => CancelHotkeyRecord();
            behav.Controls.Add(_hotkeyBox, 1, 1);
            var hkBtn = new Button { Text = "變更…", AutoSize = true };
            hkBtn.Click += (s, e) => BeginHotkeyRecord();
            behav.Controls.Add(hkBtn, 2, 1);
            _hotkeyStatus = new Label { AutoSize = true, Margin = new Padding(3, 7, 3, 3), ForeColor = Color.DimGray };
            behav.Controls.Add(_hotkeyStatus, 1, 2);
            behav.Controls.Add(new Label { Text = "點「變更…」後，直接按下想要的組合鍵（如 Ctrl+Shift+L）", AutoSize = true, ForeColor = Color.DimGray, Margin = new Padding(3, 2, 3, 3) }, 1, 3);
            left.Controls.Add(behav);

            left.Controls.Add(SectionLabel("鎖屏顯示"));
            _showClock = new CheckBox { Text = "顯示時鐘（畫面中央，字級隨螢幕自動縮放）", AutoSize = true, Margin = new Padding(3, 4, 3, 4) };
            _showClock.CheckedChanged += (s, e) => { Pull(); UpdatePreview(); };
            left.Controls.Add(_showClock);
            _showTerminal = new CheckBox { Text = "顯示終端特效（鎖屏疊加滾動日誌，純裝飾）", AutoSize = true, Margin = new Padding(3, 4, 3, 4) };
            _showTerminal.CheckedChanged += (s, e) => { if (_termStyle != null) _termStyle.Enabled = _showTerminal.Checked; Pull(); UpdatePreview(); };
            left.Controls.Add(_showTerminal);

            var termPanel = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Top };
            termPanel.Controls.Add(new Label { Text = "風格", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(18, 7, 3, 3) }, 0, 0);
            _termStyle = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 280 };
            _termStyle.Items.AddRange(new object[] { "駭客終端（隨機綠字指令）", "仿真守護終端（StillGuard 擬真日誌）" });
            _termStyle.SelectedIndexChanged += (s, e) => { Pull(); UpdatePreview(); };
            termPanel.Controls.Add(_termStyle, 1, 0);
            left.Controls.Add(termPanel);

            _fakeUpdate = new CheckBox { Text = "偽 Windows 更新畫面（黑底旋轉圈，啟用時蓋過背景/時鐘/終端）", AutoSize = true, Margin = new Padding(3, 4, 3, 4) };
            _fakeUpdate.CheckedChanged += (s, e) => { if (_fakeUpdateLang != null) _fakeUpdateLang.Enabled = _fakeUpdate.Checked; Pull(); UpdatePreview(); };
            left.Controls.Add(_fakeUpdate);

            var fuPanel = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Top };
            fuPanel.Controls.Add(new Label { Text = "語言", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(18, 7, 3, 3) }, 0, 0);
            _fakeUpdateLang = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
            _fakeUpdateLang.Items.AddRange(new object[] { "中文", "English" });
            _fakeUpdateLang.SelectedIndexChanged += (s, e) => { Pull(); UpdatePreview(); };
            fuPanel.Controls.Add(_fakeUpdateLang, 1, 0);
            left.Controls.Add(fuPanel);

            left.Controls.Add(SectionLabel("變更主密碼"));
            var pwPanel = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Top };
            pwPanel.Controls.Add(new Label { Text = "新密碼", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 0);
            _pw1 = new TextBox { Width = 200, UseSystemPasswordChar = true };
            pwPanel.Controls.Add(_pw1, 1, 0);
            pwPanel.Controls.Add(new Label { Text = "確認密碼", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 1);
            _pw2 = new TextBox { Width = 200, UseSystemPasswordChar = true };
            pwPanel.Controls.Add(_pw2, 1, 1);
            var pwBtn = new Button { Text = "套用新密碼", AutoSize = true };
            pwBtn.Click += ApplyPassword;
            pwPanel.Controls.Add(pwBtn, 1, 2);
            left.Controls.Add(pwPanel);
            _pwStatus = new Label { AutoSize = true, ForeColor = Color.DimGray, Margin = new Padding(3, 4, 3, 8) };
            left.Controls.Add(_pwStatus);

            left.Controls.Add(SectionLabel("救援碼（可選 · 忘記主密碼時的後路）"));
            var rsPanel = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Top };
            rsPanel.Controls.Add(new Label { Text = "救援碼", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 0);
            _rescue1 = new TextBox { Width = 200, UseSystemPasswordChar = true };
            rsPanel.Controls.Add(_rescue1, 1, 0);
            rsPanel.Controls.Add(new Label { Text = "確認救援碼", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 1);
            _rescue2 = new TextBox { Width = 200, UseSystemPasswordChar = true };
            rsPanel.Controls.Add(_rescue2, 1, 1);
            var rsBtn = new Button { Text = "套用救援碼", AutoSize = true };
            rsBtn.Click += ApplyRescue;
            rsPanel.Controls.Add(rsBtn, 1, 2);
            var rsClear = new Button { Text = "清除救援碼", AutoSize = true };
            rsClear.Click += ClearRescue;
            rsPanel.Controls.Add(rsClear, 1, 3);
            left.Controls.Add(rsPanel);
            _rescueStatus = new Label { AutoSize = true, ForeColor = Color.DimGray, Margin = new Padding(3, 4, 3, 8) };
            left.Controls.Add(_rescueStatus);

            // ── OTP 一次性救援碼（送至手機 / APP）──
            left.Controls.Add(SectionLabel("OTP 一次性救援碼（送至手機 / APP）"));
            _otpEnabled = new CheckBox { Text = "啟用 OTP 救援（鎖屏按 F2 寄送一次性碼）", AutoSize = true, Margin = new Padding(3, 4, 3, 4) };
            left.Controls.Add(_otpEnabled);

            var otpPanel = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Top };
            otpPanel.Controls.Add(new Label { Text = "通道", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 0);
            _otpChannel = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
            _otpChannel.Items.AddRange(new object[] { "telegram", "discord", "ntfy" });
            _otpChannel.SelectedIndexChanged += (s, e) => UpdateOtpFieldVisibility();
            otpPanel.Controls.Add(_otpChannel, 1, 0);

            otpPanel.Controls.Add(new Label { Text = "Telegram Token", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 1);
            _tgToken = new TextBox { Width = 260, UseSystemPasswordChar = true };
            otpPanel.Controls.Add(_tgToken, 1, 1);
            otpPanel.Controls.Add(new Label { Text = "Telegram ChatId", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 2);
            _tgChatId = new TextBox { Width = 260 };
            otpPanel.Controls.Add(_tgChatId, 1, 2);

            otpPanel.Controls.Add(new Label { Text = "Discord Webhook", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 3);
            _dcWebhook = new TextBox { Width = 260, UseSystemPasswordChar = true };
            otpPanel.Controls.Add(_dcWebhook, 1, 3);

            otpPanel.Controls.Add(new Label { Text = "ntfy 伺服器", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 4);
            _ntfyServer = new TextBox { Width = 260 };
            otpPanel.Controls.Add(_ntfyServer, 1, 4);
            otpPanel.Controls.Add(new Label { Text = "ntfy 主題", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) }, 0, 5);
            _ntfyTopic = new TextBox { Width = 260 };
            otpPanel.Controls.Add(_ntfyTopic, 1, 5);

            var otpBtns = new FlowLayoutPanel { AutoSize = true };
            var otpApply = new Button { Text = "套用 OTP 設定", AutoSize = true };
            otpApply.Click += ApplyOtp;
            var otpTest = new Button { Text = "測試寄送", AutoSize = true };
            otpTest.Click += TestOtp;
            otpBtns.Controls.Add(otpApply);
            otpBtns.Controls.Add(otpTest);
            otpPanel.Controls.Add(otpBtns, 1, 6);
            left.Controls.Add(otpPanel);

            _otpStatus = new Label { AutoSize = true, ForeColor = Color.DimGray, Margin = new Padding(3, 4, 3, 8), MaximumSize = new Size(420, 0) };
            left.Controls.Add(_otpStatus);

            // 底部按鈕列
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = 48, Padding = new Padding(8) };
            var lockBtn = new Button { Text = "🔒 立即鎖定", AutoSize = true, Height = 32, BackColor = Color.FromArgb(40, 90, 160), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            lockBtn.Click += (s, e) => LockNow();
            var saveBtn = new Button { Text = "儲存設定", AutoSize = true, Height = 32 };
            saveBtn.Click += (s, e) => { Pull(); SaveConfig(); };
            buttons.Controls.Add(lockBtn);
            buttons.Controls.Add(saveBtn);
            split.Panel1.Controls.Add(buttons);
            buttons.BringToFront();

            // ===== 右側預覽 =====
            var right = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10), BackColor = Color.FromArgb(30, 30, 34) };
            split.Panel2.Controls.Add(right);

            var previewBar = new Panel { Dock = DockStyle.Top, Height = 30 };
            var previewTitle = new Label { Text = "即時預覽（鎖屏外觀）", Dock = DockStyle.Left, ForeColor = Color.Gainsboro, AutoSize = true, Padding = new Padding(0, 6, 0, 0) };
            var refreshBtn = new Button { Text = "重新擷取桌面", Dock = DockStyle.Right, AutoSize = true, FlatStyle = FlatStyle.Flat, ForeColor = Color.Gainsboro };
            refreshBtn.Click += (s, e) => RecaptureDesktopForPreview();
            previewBar.Controls.Add(previewTitle);
            previewBar.Controls.Add(refreshBtn);

            _preview = new PreviewPanel { Dock = DockStyle.Fill };
            right.Controls.Add(_preview);
            right.Controls.Add(previewBar);
        }

        // 隱藏視窗→擷取當下乾淨桌面→還原，讓預覽反映現況
        private void RecaptureDesktopForPreview()
        {
            Hide();
            Application.DoEvents();
            Thread.Sleep(150);
            _preview.RefreshDesktop();
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        private static Label SectionLabel(string text)
        {
            return new Label
            {
                Text = text,
                AutoSize = true,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                Margin = new Padding(0, 12, 0, 4),
                ForeColor = Color.FromArgb(40, 90, 160)
            };
        }

        // ---- 資料繫結 ----
        private void BindFromConfig()
        {
            // 設定控制項值會觸發 ValueChanged/SelectedIndexChanged → Pull()，
            // 若此時表格尚未填好，會把 widgets 清空。故載入期間以 _binding 抑制回寫。
            _binding = true;
            try
            {
                _bgType.SelectedItem = MatchBgType(_cfg.background.type);
                if (_bgType.SelectedItem == null) _bgType.SelectedIndex = 0;
                _blur.Value = Clamp(_cfg.background.blur, 0, 60);
                _dim.Value = Clamp((int)Math.Round(_cfg.background.dim * 100), 0, 100);
                _imagePath.Text = _cfg.background.path ?? "";
                _idle.Value = Clamp(_cfg.idleTimeoutSec, 3, 120);
                _hotkeyBox.Text = string.IsNullOrWhiteSpace(_cfg.hotkey) ? "" : _cfg.hotkey;

                _showClock.Checked = _cfg.showClock;
                _showTerminal.Checked = _cfg.showTerminal;
                _termStyle.SelectedIndex = ((_cfg.terminalStyle ?? "").Trim().ToLowerInvariant() == "guard") ? 1 : 0;
                _termStyle.Enabled = _cfg.showTerminal;
                _fakeUpdate.Checked = _cfg.fakeUpdate;
                _fakeUpdateLang.SelectedIndex = ((_cfg.fakeUpdateLang ?? "").Trim().ToLowerInvariant() == "en") ? 1 : 0;
                _fakeUpdateLang.Enabled = _cfg.fakeUpdate;

                var o = _cfg.otp ?? new OtpConfig();
                _otpEnabled.Checked = o.enabled;
                _otpChannel.SelectedItem = (o.channel == "discord" || o.channel == "ntfy") ? o.channel : "telegram";
                if (_otpChannel.SelectedItem == null) _otpChannel.SelectedIndex = 0;
                _tgToken.Text = DataProtector.Unprotect(o.telegramToken);     // 顯示明碼供編輯
                _tgChatId.Text = o.telegramChatId ?? "";
                _dcWebhook.Text = DataProtector.Unprotect(o.discordWebhook);
                _ntfyServer.Text = string.IsNullOrEmpty(o.ntfyServer) ? "https://ntfy.sh" : o.ntfyServer;
                _ntfyTopic.Text = o.ntfyTopic ?? "";
                UpdateOtpFieldVisibility();
                RefreshOtpStatus();

                RefreshPwdStatus();
            }
            finally { _binding = false; }

            _preview.SetConfig(_cfg);
        }

        private string MatchBgType(string t)
        {
            t = (t ?? "").ToLowerInvariant();
            foreach (var item in _bgType.Items)
                if (item.ToString().ToLowerInvariant() == t) return item.ToString();
            return null;
        }

        // 將 UI 值寫回 _cfg（不存檔）
        private void Pull()
        {
            if (_binding) return;   // 載入設定到畫面期間不可回寫（否則會用半成品畫面覆蓋設定）
            _cfg.background.type = _bgType.SelectedItem != null ? _bgType.SelectedItem.ToString() : "blurDesktop";
            _cfg.background.blur = (int)_blur.Value;
            _cfg.background.dim = (double)_dim.Value / 100.0;
            _cfg.background.path = string.IsNullOrWhiteSpace(_imagePath.Text) ? null : _imagePath.Text.Trim();
            _cfg.idleTimeoutSec = (int)_idle.Value;
            // 錄製中欄位顯示的是提示字，不可當成熱鍵值寫入
            if (!_hotkeyRecording) _cfg.hotkey = (_hotkeyBox.Text ?? "").Trim();
            _cfg.showClock = _showClock.Checked;
            _cfg.showTerminal = _showTerminal.Checked;
            _cfg.terminalStyle = _termStyle.SelectedIndex == 1 ? "guard" : "hacker";
            _cfg.fakeUpdate = _fakeUpdate.Checked;
            _cfg.fakeUpdateLang = _fakeUpdateLang.SelectedIndex == 1 ? "en" : "zh";
        }

        private void UpdatePreview() { _preview.SetConfig(_cfg); }

        // ---- 動作 ----
        private void BrowseImage(object sender, EventArgs e)
        {
            using (var dlg = new OpenFileDialog { Filter = "圖片檔|*.png;*.jpg;*.jpeg;*.bmp|所有檔案|*.*" })
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    _imagePath.Text = dlg.FileName;
                    if (MatchBgType("image") != null) _bgType.SelectedItem = MatchBgType("image");
                    Pull(); UpdatePreview();
                }
        }

        private void ApplyPassword(object sender, EventArgs e)
        {
            string a = _pw1.Text, b = _pw2.Text;
            if (string.IsNullOrEmpty(a))
            {
                MessageBox.Show(this, "新密碼不可為空。", "變更密碼", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (a != b)
            {
                MessageBox.Show(this, "兩次輸入不一致。", "變更密碼", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            PasswordManager.SetPassword(_cfg, a);
            Pull();
            SaveConfig();
            _pw1.Clear(); _pw2.Clear();
            RefreshPwdStatus();
            MessageBox.Show(this, "主密碼已更新並儲存。", "變更密碼", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ApplyRescue(object sender, EventArgs e)
        {
            string a = _rescue1.Text, b = _rescue2.Text;
            if (string.IsNullOrEmpty(a))
            {
                MessageBox.Show(this, "救援碼不可為空（若要移除請按「清除救援碼」）。", "救援碼", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (a != b)
            {
                MessageBox.Show(this, "兩次輸入不一致。", "救援碼", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            PasswordManager.SetRescue(_cfg, a);
            SaveConfig();
            _rescue1.Clear(); _rescue2.Clear();
            RefreshPwdStatus();
            MessageBox.Show(this, "救援碼已設定並儲存。", "救援碼", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ClearRescue(object sender, EventArgs e)
        {
            PasswordManager.SetRescue(_cfg, null);
            SaveConfig();
            _rescue1.Clear(); _rescue2.Clear();
            RefreshPwdStatus();
            MessageBox.Show(this, "救援碼已清除。", "救援碼", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // 依選擇的通道，只啟用該通道需要的欄位
        private void UpdateOtpFieldVisibility()
        {
            string ch = _otpChannel.SelectedItem != null ? _otpChannel.SelectedItem.ToString() : "telegram";
            bool tg = ch == "telegram", dc = ch == "discord", nt = ch == "ntfy";
            _tgToken.Enabled = tg; _tgChatId.Enabled = tg;
            _dcWebhook.Enabled = dc;
            _ntfyServer.Enabled = nt; _ntfyTopic.Enabled = nt;
        }

        // 從 UI 收集 OTP 設定到一個 OtpConfig（機密欄位加密）
        private OtpConfig CollectOtp()
        {
            return new OtpConfig
            {
                enabled = _otpEnabled.Checked,
                channel = _otpChannel.SelectedItem != null ? _otpChannel.SelectedItem.ToString() : "telegram",
                telegramToken = DataProtector.Protect(_tgToken.Text.Trim()),
                telegramChatId = _tgChatId.Text.Trim(),
                discordWebhook = DataProtector.Protect(_dcWebhook.Text.Trim()),
                ntfyServer = string.IsNullOrWhiteSpace(_ntfyServer.Text) ? "https://ntfy.sh" : _ntfyServer.Text.Trim(),
                ntfyTopic = _ntfyTopic.Text.Trim()
            };
        }

        private void ApplyOtp(object sender, EventArgs e)
        {
            _cfg.otp = CollectOtp();
            SaveConfig();
            RefreshOtpStatus();
            MessageBox.Show(this, "OTP 設定已儲存（機密以 DPAPI 加密存放於本機）。", "OTP", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void TestOtp(object sender, EventArgs e)
        {
            var o = CollectOtp();
            if (!NotifierFactory.IsConfigured(o))
            {
                MessageBox.Show(this, "尚未填妥所選通道的必要欄位。", "測試寄送", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            _otpStatus.Text = "測試寄送中…";
            var t = new Thread(() =>
            {
                INotifier n = NotifierFactory.Create(o);
                string err = "通道建立失敗";
                bool ok = (n != null) && n.Send("【StillGuard 靜守】測試訊息：若你收到這則，代表 OTP 通道設定成功。", out err);
                string msg = ok ? "測試訊息已寄出，請查看你的裝置。" : ("寄送失敗：" + (err ?? "未知錯誤"));
                try { BeginInvoke((MethodInvoker)(() => { _otpStatus.Text = msg; _otpStatus.ForeColor = ok ? Color.SeaGreen : Color.Firebrick; })); } catch { }
            });
            t.IsBackground = true;
            t.Start();
        }

        private void RefreshOtpStatus()
        {
            if (_otpStatus == null) return;
            if (NotifierFactory.IsConfigured(_cfg.otp))
            {
                _otpStatus.Text = "目前：OTP 已啟用（通道 " + _cfg.otp.channel + "）。";
                _otpStatus.ForeColor = Color.SeaGreen;
            }
            else
            {
                _otpStatus.Text = "目前：OTP 未啟用或未設定完整。";
                _otpStatus.ForeColor = Color.DimGray;
            }
        }

        private void RefreshPwdStatus()
        {
            if (_pwStatus != null)
                _pwStatus.Text = PasswordManager.HasMaster(_cfg)
                    ? "目前：已設定主密碼。"
                    : "⚠ 尚未設定主密碼——請先在此設定，才能使用鎖定。";
            if (_pwStatus != null)
                _pwStatus.ForeColor = PasswordManager.HasMaster(_cfg) ? Color.DimGray : Color.Firebrick;
            if (_rescueStatus != null)
                _rescueStatus.Text = PasswordManager.HasRescue(_cfg) ? "目前：已設定救援碼。" : "目前：未設定救援碼（可不設）。";
        }

        private void SaveConfig()
        {
            try { _cfg.Save(_cfgPath); }
            catch (Exception ex)
            {
                MessageBox.Show(this, "儲存失敗：" + ex.Message, "錯誤", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void LockNow()
        {
            // 防重入：鎖定中再按熱鍵 / 按鈕一律忽略。
            if (_isLocking) return;
            // 解鎖後短暫冷卻：擋掉解鎖那顆 Enter 的 autorepeat 殘留所誤觸的重複鎖定。
            if (DateTime.Now < _lockCooldownUntil) return;

            // 主密碼必設：未設定不允許鎖定，避免把自己鎖死。
            if (!PasswordManager.HasMaster(_cfg))
            {
                RestoreFromTray();
                RefreshPwdStatus();
                MessageBox.Show(this, "尚未設定主密碼，無法鎖定。\n請先在「變更主密碼」設定一組密碼。", "尚未設定密碼", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                if (_pw1 != null) { _pw1.Focus(); }
                return;
            }

            // 記住鎖定前設定視窗的狀態：若原本縮在系統匣（隱藏），解鎖後應維持隱藏，不該自動跳出。
            bool wasVisible = Visible && WindowState != FormWindowState.Minimized;

            _isLocking = true;
            Pull();
            SaveConfig();
            Hide();
            // 讓設定視窗確實消失後再截背景
            Application.DoEvents();
            Thread.Sleep(180);
            try
            {
                using (var lf = new LockForm(_cfg))
                    lf.ShowDialog();
            }
            finally
            {
                _isLocking = false;
                _lockCooldownUntil = DateTime.Now.AddMilliseconds(800);

                if (wasVisible)
                {
                    // 原本開著設定視窗 → 解鎖後回到設定視窗
                    Show();
                    WindowState = FormWindowState.Normal;
                    Activate();
                    // 清除焦點：避免解鎖殘留的 Enter 落到「立即鎖定」鈕而再次鎖定。
                    ActiveControl = null;
                    _preview.RefreshDesktop();
                }
                // 原本縮在系統匣 → 維持隱藏，解鎖後乖乖回托盤，不打擾老爺。
            }
        }

        // ---- 全域熱鍵 ----
        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            RegisterLockHotkey(false);
        }

        // silent=false 時，註冊失敗會提示使用者。
        private void RegisterLockHotkey(bool announce)
        {
            if (!IsHandleCreated) return;

            if (_hotkeyRegistered)
            {
                NativeMethods.UnregisterHotKey(Handle, HOTKEY_ID);
                _hotkeyRegistered = false;
            }

            uint mods, vk;
            if (!ParseHotkey(_cfg.hotkey, out mods, out vk))
            {
                SetHotkeyStatus("✗ 未啟用（格式無法解析或留空）", Color.DimGray);
                if (announce) MessageBox.Show(this, "快捷鍵格式無法解析，例：Ctrl+Alt+L", "快捷鍵", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            bool ok = NativeMethods.RegisterHotKey(Handle, HOTKEY_ID, mods | NativeMethods.MOD_NOREPEAT, vk);
            _hotkeyRegistered = ok;
            if (ok)
                SetHotkeyStatus("✓ 已啟用：" + _cfg.hotkey, Color.SeaGreen);
            else
                SetHotkeyStatus("✗ 註冊失敗：" + _cfg.hotkey + "（可能被其他程式占用，請換一組）", Color.Firebrick);

            if (announce)
            {
                if (ok) MessageBox.Show(this, "已套用快捷鍵：" + _cfg.hotkey, "快捷鍵", MessageBoxButtons.OK, MessageBoxIcon.Information);
                else MessageBox.Show(this, "快捷鍵註冊失敗，可能已被其他程式占用：" + _cfg.hotkey + "\n請改用其他組合（例如 Ctrl+Alt+K、Ctrl+Shift+L）。", "快捷鍵", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void SetHotkeyStatus(string text, Color color)
        {
            if (_hotkeyStatus == null) return;
            _hotkeyStatus.Text = text;
            _hotkeyStatus.ForeColor = color;
        }

        // ---- 快捷鍵錄製：點一下後直接按組合鍵 ----
        private void BeginHotkeyRecord()
        {
            if (_hotkeyRecording) return;
            _hotkeyRecording = true;
            _hotkeyBox.Text = "請按下組合鍵…（Esc 取消）";
            SetHotkeyStatus("錄製中：按住 Ctrl / Alt / Shift 其中至少一個，再按一個鍵", Color.RoyalBlue);
            _hotkeyBox.Focus();
        }

        private void CancelHotkeyRecord()
        {
            if (!_hotkeyRecording) return;
            _hotkeyRecording = false;
            _hotkeyBox.Text = _cfg.hotkey ?? "";
            RegisterLockHotkey(false);   // 還原狀態列顯示
        }

        private void HotkeyBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (!_hotkeyRecording) return;
            e.SuppressKeyPress = true;
            e.Handled = true;

            if (e.KeyCode == Keys.Escape) { CancelHotkeyRecord(); return; }

            // 按到的是修飾鍵本身 → 還在等待主鍵
            if (e.KeyCode == Keys.ControlKey || e.KeyCode == Keys.ShiftKey || e.KeyCode == Keys.Menu
                || e.KeyCode == Keys.LWin || e.KeyCode == Keys.RWin)
            {
                var pend = ModList(e);
                SetHotkeyStatus("錄製中：" + (pend.Count > 0 ? string.Join("+", pend.ToArray()) + "+…" : "請按住 Ctrl / Alt / Shift…"), Color.RoyalBlue);
                return;
            }

            string key = KeyToString(e.KeyCode);
            if (key == null)
            {
                SetHotkeyStatus("不支援的按鍵，請用 字母 / 數字 / F1–F12", Color.Firebrick);
                return;
            }
            var mods = ModList(e);
            if (mods.Count == 0)
            {
                SetHotkeyStatus("請至少搭配一個 Ctrl / Alt / Shift，避免誤觸", Color.Firebrick);
                return;
            }

            string combo = string.Join("+", mods.ToArray()) + "+" + key;
            _hotkeyBox.Text = combo;
            _hotkeyRecording = false;
            Pull();                 // 同步至 _cfg（此時讀到 combo）
            SaveConfig();
            RegisterLockHotkey(false);
        }

        private static List<string> ModList(KeyEventArgs e)
        {
            var mods = new List<string>();
            if (e.Control) mods.Add("Ctrl");
            if (e.Alt) mods.Add("Alt");
            if (e.Shift) mods.Add("Shift");
            return mods;
        }

        private static string KeyToString(Keys k)
        {
            if (k >= Keys.A && k <= Keys.Z) return k.ToString();
            if (k >= Keys.D0 && k <= Keys.D9) return ((char)('0' + (k - Keys.D0))).ToString();
            if (k >= Keys.NumPad0 && k <= Keys.NumPad9) return ((char)('0' + (k - Keys.NumPad0))).ToString();
            if (k >= Keys.F1 && k <= Keys.F12) return k.ToString();
            return null;
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == NativeMethods.WM_HOTKEY && m.WParam.ToInt32() == HOTKEY_ID)
            {
                LockNow();
                return;
            }
            base.WndProc(ref m);
        }

        // 解析 "Ctrl+Alt+L" → 修飾鍵與虛擬鍵碼
        private static bool ParseHotkey(string text, out uint mods, out uint vk)
        {
            mods = 0; vk = 0;
            if (string.IsNullOrWhiteSpace(text)) return false;
            foreach (var raw in text.Split('+'))
            {
                string p = raw.Trim().ToLowerInvariant();
                if (p.Length == 0) continue;
                switch (p)
                {
                    case "ctrl": case "control": mods |= NativeMethods.MOD_CONTROL; break;
                    case "alt": mods |= NativeMethods.MOD_ALT; break;
                    case "shift": mods |= NativeMethods.MOD_SHIFT; break;
                    case "win": case "windows": case "meta": mods |= NativeMethods.MOD_WIN; break;
                    default:
                        if (p.Length == 1 && p[0] >= 'a' && p[0] <= 'z') vk = (uint)char.ToUpperInvariant(p[0]);
                        else if (p.Length == 1 && p[0] >= '0' && p[0] <= '9') vk = (uint)p[0];
                        else if ((p[0] == 'f') && p.Length <= 3)
                        {
                            int n;
                            if (int.TryParse(p.Substring(1), out n) && n >= 1 && n <= 24) vk = (uint)(0x70 + (n - 1));
                        }
                        break;
                }
            }
            return vk != 0 && mods != 0;   // 要求至少一個修飾鍵，避免誤觸
        }

        // ---- 系統匣 ----
        private void BuildTray()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("開啟設定", null, (s, e) => RestoreFromTray());
            menu.Items.Add("立即鎖定", null, (s, e) => { RestoreFromTray(); LockNow(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("結束", null, (s, e) => { _reallyExit = true; Close(); });

            _tray = new NotifyIcon
            {
                Icon = Icon ?? SystemIcons.Shield,   // 與視窗圖示一致
                Text = "StillGuard 靜守",
                Visible = true,
                ContextMenuStrip = menu
            };
            _tray.DoubleClick += (s, e) => RestoreFromTray();
        }

        private void RestoreFromTray()
        {
            // 視窗此刻仍隱藏（桌面乾淨），趁機把預覽更新成當下桌面
            if (_preview != null && !Visible) { try { _preview.RefreshDesktop(); } catch { } }
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            // 使用者按右上角 X → 縮到系統匣，不結束程式
            if (!_reallyExit && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                _tray.ShowBalloonTip(1500, "StillGuard 靜守", "已縮到系統匣，右鍵圖示可開設定或鎖定。", ToolTipIcon.Info);
                return;
            }
            if (_hotkeyRegistered && IsHandleCreated)
            {
                NativeMethods.UnregisterHotKey(Handle, HOTKEY_ID);
                _hotkeyRegistered = false;
            }
            if (_tray != null) { _tray.Visible = false; _tray.Dispose(); }
        }

        private static int Clamp(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }
    }

    // =========================================================================
    //  應用程式圖示載入：優先 exe 旁的 icon.ico（可隨時換、免重編），
    //  其次 exe 內嵌圖示（編譯時 /win32icon），最後回退系統盾牌。
    // =========================================================================
    internal static class AppIcon
    {
        public static Icon Load()
        {
            try
            {
                string dir = Path.GetDirectoryName(Application.ExecutablePath);
                string ico = Path.Combine(dir, "icon.ico");
                if (File.Exists(ico)) return new Icon(ico);
            }
            catch { }
            try
            {
                var embedded = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
                if (embedded != null) return embedded;
            }
            catch { }
            return SystemIcons.Shield;
        }
    }

    // =========================================================================
    //  進入點
    // =========================================================================
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            // 必須在任何視窗 / 繪圖之前宣告 DPI 感知，截圖與座標才會用實體像素。
            NativeMethods.EnableDpiAwareness();

            // 單一實例：避免重複鎖定造成鉤子疊加
            bool createdNew;
            using (var mutex = new Mutex(true, "StillGuard_SingleInstance", out createdNew))
            {
                if (!createdNew) return;

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                string exeDir = Path.GetDirectoryName(Application.ExecutablePath);
                string cfgPath = Path.Combine(exeDir, "config.json");

                // 主視窗即設定面板（依老爺指示）。鎖定由面板內按鈕或系統匣觸發。
                Application.Run(new SettingsForm(cfgPath));
            }
        }
    }
}
