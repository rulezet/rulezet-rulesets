rule MAL_BurningUmbrella_Sample_11_RID31D5 : APT DEMO FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:39:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "278e9d130678615d0fee4d7dd432f0dda6d52b0719649ee58cbdca097e997c3f"
      tags = "APT, DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Resume.app/Contents/Java/Resume.jarPK" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 700KB and 1 of them
}