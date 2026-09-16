rule Empire_Invoke_EgressCheck {
   meta:
      description = "Detects Empire component - file Invoke-EgressCheck.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "e2d270266abe03cfdac66e6fc0598c715e48d6d335adf09a9ed2626445636534"
      id = "21e09250-6853-5743-a6ef-aa6be8091d33"
   strings:
      $s1 = "egress -ip $ip -port $c -delay $delay -protocol $protocol" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 10KB and 1 of them ) or all of them
}