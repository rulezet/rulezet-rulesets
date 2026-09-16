rule CN_Honker_ShiftBackdoor_Server_RID32C0 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Server.dat"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:18:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "del /q /f %systemroot%system32sethc.exe" fullword ascii
      $s1 = "cacls %s /t /c /e /r administrators" fullword ascii
      $s2 = "\\dllcache\\sethc.exe" ascii
      $s3 = "\\ntvdm.exe" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 2 of them
}