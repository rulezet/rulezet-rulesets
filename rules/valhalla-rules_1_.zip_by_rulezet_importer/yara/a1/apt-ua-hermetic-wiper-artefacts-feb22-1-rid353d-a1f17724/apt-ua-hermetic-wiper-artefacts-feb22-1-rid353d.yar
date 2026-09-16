rule APT_UA_Hermetic_Wiper_Artefacts_Feb22_1_RID353D : APT DEMO T1021_002 T1105 T1218_011 {
   meta:
      description = "Detects artefacts found in Hermetic Wiper malware related intrusions"
      author = "Florian Roth"
      reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia"
      date = "2022-02-25 16:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, T1021_002, T1105, T1218_011"
      minimum_yara = "3.5.0"
      
   strings:
      $sx1 = "/c powershell -c \"rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump" ascii wide
      $sx2 = "appdata\\local\\microsoft\\windows\\winupd.log" ascii wide
      $sx3 = "AppData\\Local\\Microsoft\\Windows\\Winupd.log" ascii wide
      $sx4 = "CSIDL_SYSTEM_DRIVE\\temp\\sys.tmp1" ascii wide
      $sx5 = "\\policydefinitions\\postgresql.exe" ascii wide
      $sx6 = "powershell -v 2 -exec bypass -File text.ps1" ascii wide
      $sx7 = "powershell -exec bypass gp.ps1" ascii wide
      $sx8 = "powershell -exec bypass -File link.ps1" ascii wide
      $sx9 = " 1> \\\\127.0.0.1\\ADMIN$\\__16" ascii wide
      $sa1 = "(New-Object System.Net.WebClient).DownloadFile(" ascii wide
      $sa2 = "CSIDL_SYSTEM_DRIVE\\temp\\" ascii wide
      $sa3 = "1> \\\\127.0.0.1\\ADMIN$" ascii wide
      $fp1 = "<html" ascii
   condition: 
      1 of ( $sx* ) or all of ( $sa* ) and not 1 of ( $fp* )
}