rule BeepService_Hacktool_RID2EF2 : CHINA DEMO EXE FILE HKTL T1021_002 {
   meta:
      description = "Detects BeepService Hacktool used by Chinese APT groups"
      author = "Florian Roth"
      reference = "https://www.secureworks.com/research/analysis-of-dhs-nccic-indicators"
      date = "2016-05-12 11:36:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "032df812a68852b6f3822b9eac4435e531ca85bdaf3ee99c669134bd16e72820"
      hash2 = "e30933fcfc9c2a7443ee2f23a3df837ca97ea5653da78f782e2884e5a7b734f7"
      hash3 = "ebb9c4f7058e19b006450b8162910598be90428998df149977669e61a0b7b9ed"
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1021_002"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\\\%s\\admin$\\system32\\%s" fullword ascii
      $s1 = "123.exe" fullword ascii
      $s2 = "regclean.exe" fullword ascii
      $s3 = "192.168.88.69" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and $x1 and 1 of ( $s* )
}