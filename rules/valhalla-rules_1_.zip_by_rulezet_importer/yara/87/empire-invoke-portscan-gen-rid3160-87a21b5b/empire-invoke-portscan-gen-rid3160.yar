rule Empire_Invoke_Portscan_Gen_RID3160 : DEMO GEN SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - from files Invoke-Portscan.ps1, Invoke-Portscan.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 13:19:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash2 = "cf7030be01fab47e79e4afc9e0d4857479b06a5f68654717f3bc1bc67a0f38d3"
      tags = "DEMO, GEN, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Test-Port -h $h -p $Port -timeout $Timeout" fullword ascii
      $s2 = "1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 100KB and 1 of them ) or all of them
}