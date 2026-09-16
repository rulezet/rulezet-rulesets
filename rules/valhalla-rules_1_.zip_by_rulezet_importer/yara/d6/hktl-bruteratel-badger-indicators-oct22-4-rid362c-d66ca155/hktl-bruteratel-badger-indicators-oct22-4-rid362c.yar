rule HKTL_BruteRatel_Badger_Indicators_Oct22_4_RID362C : BruteRatelC4 DEMO FILE HKTL {
   meta:
      description = "Detects Brute Ratel C4 badger indicators"
      author = "Florian Roth"
      reference = "https://twitter.com/embee_research/status/1580030310778953728"
      date = "2022-10-12 16:44:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "BruteRatelC4, DEMO, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = { b? 89 4d 39 8c } 
      $s2 = { b? bd ca 3b d3 } 
      $s3 = { b? b2 c1 06 ae } 
      $s4 = { b? 74 eb 1d 4d } 
   condition: 
      filesize < 8000KB and all of ( $s* ) and not uint8 ( 0 ) == 0x02
}