rule redSails_EXE_RID2B89 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects Red Sails Hacktool by WinDivert references"
      author = "Florian Roth"
      reference = "https://github.com/BeetleChunks/redsails"
      date = "2017-10-02 09:10:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a7861d25b0c038d77838ecbd5ea5674650ad4f5faf7432a6f3cfeb427433fac"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "bWinDivert64.dll" fullword ascii
      $s2 = "bWinDivert32.dll" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 6000KB and all of them )
}