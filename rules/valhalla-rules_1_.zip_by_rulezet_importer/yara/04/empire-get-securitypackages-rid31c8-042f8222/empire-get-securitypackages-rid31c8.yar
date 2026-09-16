rule Empire_Get_SecurityPackages_RID31C8 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Get-SecurityPackages.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 13:37:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5d06e99121cff9b0fce74b71a137501452eebbcd1e901b26bde858313ee5a9c1"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$null = $EnumBuilder.DefineLiteral('LOGON', 0x2000)" fullword ascii
      $s2 = "$EnumBuilder = $ModuleBuilder.DefineEnum('SSPI.SECPKG_FLAG', 'Public', [Int32])" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 20KB and 1 of them ) or all of them
}