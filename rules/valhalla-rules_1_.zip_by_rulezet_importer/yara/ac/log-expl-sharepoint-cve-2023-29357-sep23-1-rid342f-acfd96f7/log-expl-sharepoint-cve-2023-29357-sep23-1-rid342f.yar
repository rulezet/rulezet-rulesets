rule LOG_EXPL_SharePoint_CVE_2023_29357_Sep23_1_RID342F : CVE_2023_29357 DEMO EXPLOIT LOG {
   meta:
      description = "Detects log entries that could indicate a successful exploitation of CVE-2023-29357 on Microsoft SharePoint servers"
      author = "Florian Roth (with help from @LuemmelSec)"
      reference = "https://twitter.com/Gi7w0rm/status/1706764212704591953?s=20"
      date = "2023-09-28 15:19:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-10-01"
      tags = "CVE_2023_29357, DEMO, EXPLOIT, LOG"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1 = /GET [a-z\.\/_]{0,40}\/web\/(siteusers|currentuser) - (80|443) .{10,200} (python-requests\/[0-9\.]{3,8}|-) [^ ]{1,160} [^4]0[0-9] / 
   condition: 
      $xr1
}