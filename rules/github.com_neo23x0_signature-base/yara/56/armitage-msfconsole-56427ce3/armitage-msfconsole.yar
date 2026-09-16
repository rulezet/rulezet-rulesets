rule Armitage_msfconsole {
   meta:
      description = "Detects Armitage component"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-12-24"
      modified = "2022-08-18"
      hash1 = "662ba75c7ed5ac55a898f480ed2555d47d127a2d96424324b02724b3b2c95b6a"
      id = "9c610cd0-663e-54ea-a0f2-6c044fc45d23"
   strings:
      $s1 = "\\umeterpreter\\u >" ascii
      $s3 = "^meterpreter >" fullword ascii
      $s11 = "\\umsf\\u>" ascii
   condition:
      filesize < 1KB and 2 of them
}