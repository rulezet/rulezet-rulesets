rule WiltedTulip_Matryoshka_RAT_RID3150 : APT DEMO EXE FILE {
   meta:
      description = "Detects Matryoshka RAT used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 13:17:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6f208473df0d31987a4999eeea04d24b069fdb6a8245150aa91dfdc063cd64ab"
      hash2 = "6cc1f4ecd28b833c978c8e21a20a002459b4a6c21a4fbaad637111aa9d5b1a32"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%S:\\Users\\public" fullword wide
      $s2 = "ntuser.dat.swp" fullword wide
      $s3 = "Job Save / Load Config" fullword wide
      $s4 = ".?AVPSCL_CLASS_JOB_SAVE_CONFIG@@" fullword ascii
      $s5 = "winupdate64.com" fullword ascii
      $s6 = "Job Save KeyLogger" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 3 of them )
}