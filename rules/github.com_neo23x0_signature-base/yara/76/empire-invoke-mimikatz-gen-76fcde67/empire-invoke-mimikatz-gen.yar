rule Empire_Invoke_Mimikatz_Gen {
   meta:
      description = "Detects Empire component - file Invoke-Mimikatz.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      id = "1f771a17-2534-5811-80bd-bc1bab37d97c"
   strings:
      $s1 = "= \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ" ascii
      $s2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}