rule CN_Tools_srss_2_RID2CCD : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file srss.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:04:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "used pepack!" fullword ascii
      $s1 = "KERNEL32.dll" fullword ascii
      $s2 = "KERNEL32.DLL" fullword ascii
      $s3 = "LoadLibraryA" fullword ascii
      $s4 = "GetProcAddress" fullword ascii
      $s5 = "VirtualProtect" fullword ascii
      $s6 = "VirtualAlloc" fullword ascii
      $s7 = "VirtualFree" fullword ascii
      $s8 = "ExitProcess" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and ( $x1 at 0 ) and filesize < 14KB and all of ( $s* )
}