rule CN_Honker__D_injection_V2_32_D_injection_V2_32_D_injection_V2_32_RID3E17 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - from files D_injection_V2.32.exe, D_injection_V2.32.exe, D_injection_V2.32.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 22:22:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "upfile.asp " fullword ascii
      $s2 = "[wscript.shell]" fullword ascii
      $s3 = "XP_CMDSHELL" fullword ascii
      $s4 = "[XP_CMDSHELL]" fullword ascii
      $s5 = "http://d99net.3322.org" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 10000KB and 4 of them
}