rule Empire_Invoke_EgressCheck_RID30E4 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Invoke-EgressCheck.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:59:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e2d270266abe03cfdac66e6fc0598c715e48d6d335adf09a9ed2626445636534"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "egress -ip $ip -port $c -delay $delay -protocol $protocol" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x233c and filesize < 10KB and 1 of them ) or all of them
}