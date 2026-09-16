rule Empire_Agent_Gen_RID2D3A : DEMO GEN SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - from files agent.ps1, agent.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 10:22:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"
      tags = "DEMO, GEN, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$wc.Headers.Add(\"User-Agent\",$script:UserAgent)" fullword ascii
      $s2 = "$min = [int]((1-$script:AgentJitter)*$script:AgentDelay)" fullword ascii
      $s3 = "if ($script:AgentDelay -ne 0){" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x660a and filesize < 100KB and 1 of them ) or all of them
}