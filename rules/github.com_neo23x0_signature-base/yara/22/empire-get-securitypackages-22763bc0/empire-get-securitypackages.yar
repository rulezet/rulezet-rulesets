rule Empire_Get_SecurityPackages {
   meta:
      description = "Detects Empire component - file Get-SecurityPackages.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "5d06e99121cff9b0fce74b71a137501452eebbcd1e901b26bde858313ee5a9c1"
      id = "a109eda1-a26d-5cf6-b6b5-1a1a1e770a0a"
   strings:
      $s1 = "$null = $EnumBuilder.DefineLiteral('LOGON', 0x2000)" fullword ascii
      $s2 = "$EnumBuilder = $ModuleBuilder.DefineEnum('SSPI.SECPKG_FLAG', 'Public', [Int32])" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 20KB and 1 of them ) or all of them
}