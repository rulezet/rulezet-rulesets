rule Waterbear_1_Jun17_RID2D32 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:21:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "dd3676f478ee6f814077a12302d38426760b0701bb629f413f7bf2ec71319db5"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\Release\\svc.pdb" ascii
      $s2 = "svc.dll" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}