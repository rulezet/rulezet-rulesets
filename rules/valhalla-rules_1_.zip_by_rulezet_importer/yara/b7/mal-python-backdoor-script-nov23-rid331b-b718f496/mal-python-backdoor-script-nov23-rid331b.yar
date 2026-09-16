rule MAL_Python_Backdoor_Script_Nov23_RID331B : CVE_2023_4966 DEMO MAL RANSOM SCRIPT T1059_006 {
   meta:
      description = "Detects a trojan (written in Python) that communicates with c2 - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      author = "X__Junior"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23 14:33:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "906602ea3c887af67bcb4531bbbb459d7c24a2efcb866bcb1e3b028a51f12ae6"
      tags = "CVE_2023_4966, DEMO, MAL, RANSOM, SCRIPT, T1059_006"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "port = 443 if \"https\"" ascii
      $s2 = "winrm.Session basic error" ascii
      $s3 = "Windwoscmd.run_cmd(str(cmd))" ascii
   condition: 
      filesize < 50KB and all of them
}