rule Dos_NtGod_RID2A72 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file NtGod.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 06:01:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\temp\\NtGodMode.exe" ascii
      $s4 = "NtGodMode.exe" fullword ascii
      $s10 = "ntgod.bat" fullword ascii
      $s19 = "sfxcmd" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 250KB and all of them
}