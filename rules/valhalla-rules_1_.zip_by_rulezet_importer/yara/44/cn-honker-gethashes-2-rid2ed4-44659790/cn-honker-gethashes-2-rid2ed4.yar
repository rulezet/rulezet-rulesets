rule CN_Honker_GetHashes_2_RID2ED4 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file GetHashes.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:31:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "GetHashes.exe <SAM registry file> [System key file]" fullword ascii
      $s2 = "GetHashes.exe $Local" fullword ascii
      $s3 = "The system key doesn't match SAM registry file!" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 2 of them
}