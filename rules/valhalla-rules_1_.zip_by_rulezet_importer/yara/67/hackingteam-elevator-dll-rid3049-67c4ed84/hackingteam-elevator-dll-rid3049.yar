rule Hackingteam_Elevator_DLL_RID3049 : APT DEMO EXE FILE {
   meta:
      description = "Hacking Team Disclosure Sample - file elevator.dll"
      author = "Florian Roth"
      reference = "http://t.co/EG0qtVcKLh"
      date = "2015-07-07 12:33:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\sysnative\\CI.dll" ascii
      $s2 = "setx TOR_CONTROL_PASSWORD" fullword ascii
      $s3 = "mitmproxy0" fullword ascii
      $s4 = "\\insert_cert.exe" ascii
      $s5 = "elevator.dll" fullword ascii
      $s6 = "CRTDLL.DLL" fullword ascii
      $s7 = "fail adding cert" fullword ascii
      $s8 = "DownloadingFile" fullword ascii
      $s9 = "fail adding cert: %s" fullword ascii
      $s10 = "InternetOpenA fail" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 6 of them
}