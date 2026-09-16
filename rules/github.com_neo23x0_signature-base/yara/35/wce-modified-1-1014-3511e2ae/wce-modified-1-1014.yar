rule WCE_Modified_1_1014 {
   meta:
      description = "Modified (packed) version of Windows Credential Editor"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      hash = "09a412ac3c85cedce2642a19e99d8f903a2e0354"
      score = 70
      id = "536d1a7f-bda1-5c22-bf72-a177468e7c42"
   strings:
      $s0 = "LSASS.EXE" fullword ascii
      $s1 = "_CREDS" ascii
      $s9 = "Using WCE " ascii
   condition:
      all of them
}