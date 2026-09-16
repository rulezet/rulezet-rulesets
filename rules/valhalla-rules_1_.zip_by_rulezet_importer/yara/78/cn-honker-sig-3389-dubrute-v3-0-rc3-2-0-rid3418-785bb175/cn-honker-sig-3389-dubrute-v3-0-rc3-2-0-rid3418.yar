rule CN_Honker_sig_3389_DUBrute_v3_0_RC3_2_0_RID3418 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file 2.0.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:15:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
      $s3 = "Create %d IP@Loginl;Password" fullword ascii
      $s15 = "UBrute.com" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 980KB and 2 of them
}