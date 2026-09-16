rule IsDebug_V1_4_RID2B2D : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file IsDebug V1.4.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:55:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "IsDebug.dll" fullword ascii
      $s1 = "SV Dumper V1.0" fullword wide
      $s2 = "(IsDebuggerPresent byte Patcher)" fullword ascii
      $s8 = "Error WriteMemory failed" fullword ascii
      $s9 = "IsDebugPresent" fullword ascii
      $s10 = "idb_Autoload" fullword ascii
      $s11 = "Bin Files" fullword ascii
      $s12 = "MASM32 version" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 30KB and all of them
}