rule CN_Honker_ACCESS_brute_RID2EFA : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file ACCESS_brute.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:37:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".dns166.co" ascii
      $s2 = "SExecuteA" ascii
      $s3 = "ality/clsCom" ascii
      $s4 = "NT_SINK_AddRef" ascii
      $s5 = "WINDOWS\\Syswm" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 20KB and all of them
}