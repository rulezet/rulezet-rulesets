rule ps1_toolkit_Inveigh_BruteForce_2_RID3394 : DEMO FILE HKTL SCRIPT T1059_001 T1110 {
   meta:
      description = "Semiautomatically generated YARA rule - from files Inveigh-BruteForce.ps1"
      author = "Florian Roth"
      reference = "https://github.com/vysec/ps1-toolkit"
      date = "2016-09-04 14:53:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
      tags = "DEMO, FILE, HKTL, SCRIPT, T1059_001, T1110"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "}.NTLMv2_file_queue[0]|Out-File ${" ascii
      $s2 = "}.NTLMv2_file_queue.RemoveRange(0,1)" ascii
      $s3 = "}.NTLMv2_file_queue.Count -gt 0)" ascii
      $s4 = "}.relay_running = $false" ascii
   condition: 
      ( uint16 ( 0 ) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}