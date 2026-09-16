rule Waterbear_14_Jun17_RID2D66 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:30:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "00a1068645dbe982a9aa95e7b8202a588989cd37de2fa1b344abbc0102c27d05"
      hash2 = "53330a80b3c4f74f3f10a8621dbef4cd2427723e8b98c5b7aed58229d0c292ba"
      hash3 = "bdcb23a82ac4eb1bc9254d77d92b6f294d45501aaea678a3d21c8b188e31e68b"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "my.com/msg/util/sgthash" fullword ascii
      $s2 = "C:\\recycled" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 8000KB and all of them )
}