rule MAL_Rombertik_CarbonGrabber_Builder_Server_RID375E : DEMO EXE FILE MAL {
   meta:
      description = "Detects CarbonGrabber alias Rombertik Builder Server - file Server.exe"
      author = "Florian Roth"
      reference = "http://blogs.cisco.com/security/talos/rombertik"
      date = "2015-05-05 17:35:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "C:\\WINDOWS\\system32\\svchost.exe" fullword ascii
      $s3 = "Software\\Microsoft\\Windows\\Currentversion\\RunOnce" fullword ascii
      $s4 = "chrome.exe" fullword ascii
      $s5 = "firefox.exe" fullword ascii
      $s6 = "chrome.dll" fullword ascii
      $s7 = "@KERNEL32.DLL" fullword wide
      $s8 = "Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome" ascii
      $s10 = "&post=" fullword ascii
      $s11 = "&host=" fullword ascii
      $s12 = "Ws2_32.dll" fullword ascii
      $s16 = "&browser=" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 250KB and 8 of them
}