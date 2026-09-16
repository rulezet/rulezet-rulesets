rule CN_Honker_sig_3389_DUBrute_v3_0_RC3_3_0_RID3419 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file 3.0.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:16:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "explorer.exe http://bbs.yesmybi.net" fullword ascii
      $s1 = "LOADER ERROR" fullword ascii
      $s9 = "CryptGenRandom" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 395KB and all of them
}