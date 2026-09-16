rule CN_Honker_termsrvhack_RID2F71 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file termsrvhack.dll"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:57:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "The terminal server cannot issue a client license.  It was unable to issue the" wide
      $s6 = "%s\\%s\\%d\\%d" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1052KB and all of them
}