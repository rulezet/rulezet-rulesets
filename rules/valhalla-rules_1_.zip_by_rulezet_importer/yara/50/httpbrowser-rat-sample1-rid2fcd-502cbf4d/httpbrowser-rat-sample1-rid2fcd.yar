rule HttpBrowser_RAT_Sample1_RID2FCD : APT DEMO EXE FILE G0027 T1574_001 {
   meta:
      description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample update.hancominc.com"
      author = "Florian Roth"
      reference = "http://snip.ly/giNB"
      date = "2015-08-06 12:12:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "be334d1f8fa65a723af65200a166c2bbdb06690c8b30fafe772600e4662fc68b"
      hash2 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
      tags = "APT, DEMO, EXE, FILE, G0027, T1574_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "update.hancominc.com" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and $s0
}