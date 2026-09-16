rule Empire_Invoke_DllInjection {
   meta:
      description = "Detects Empire component - file Invoke-DllInjection.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "304031aa9eca5a83bdf1f654285d86df79cb3bba4aa8fe1eb680bd5b2878ebf0"
      id = "6aa14e8f-9801-5cd3-beb0-955e19d25503"
   strings:
      $s1 = "-Dll evil.dll" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 40KB and 1 of them ) or all of them
}