rule CN_Honker_HASH_PwDump7_RID2EDE : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file PwDump7.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:32:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%s\\SYSTEM32\\CONFIG\\SAM" fullword ascii
      $s2 = "No Users key!" fullword ascii
      $s3 = "NO PASSWORD*********************:" fullword ascii
      $s4 = "Unable to dump file %S" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 380KB and all of them
}