rule CN_Honker_HASH_pwhash_RID2ED5 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file pwhash.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:31:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Example: quarks-pwdump.exe --dump-hash-domain --with-history" fullword ascii
      $s2 = "quarks-pwdump.exe <options> <NTDS file>" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 1 of them
}