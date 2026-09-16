rule Industroyer_Portscan_3_Output {
   meta:
      description = "Detects Industroyer related custom port scaner output file"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      id = "4469f056-674c-5a44-84a5-12a65b8586d5"
   strings:
      $s1 = "WSA library load complite." fullword ascii
      $s2 = "Connection refused" fullword ascii
   condition:
      all of them
}