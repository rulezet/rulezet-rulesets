rule Empire_KeePassConfig_Gen {
   meta:
      description = "Detects Empire component - from files KeePassConfig.ps1, KeePassConfig.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash2 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
      id = "e2bc88c5-50f8-5ddc-a449-41929b1d0528"
   strings:
      $s1 = "$KeePassXML = [xml](Get-Content -Path $KeePassXMLPath)" fullword ascii
   condition:
      ( uint16(0) == 0x7223 and filesize < 80KB and 1 of them ) or all of them
}