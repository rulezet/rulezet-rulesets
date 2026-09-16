rule Empire_Invoke_PostExfil {
   meta:
      description = "Detects Empire component - file Invoke-PostExfil.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "00c0479f83c3dbbeff42f4ab9b71ca5fe8cd5061cb37b7b6861c73c54fd96d3e"
      id = "58d9e057-efde-56ab-9b7e-982342a910e2"
   strings:
      $s1 = "# upload to a specified exfil URI" fullword ascii
      $s2 = "Server path to exfil to." fullword ascii
   condition:
      ( uint16(0) == 0x490a and filesize < 2KB and 1 of them ) or all of them
}