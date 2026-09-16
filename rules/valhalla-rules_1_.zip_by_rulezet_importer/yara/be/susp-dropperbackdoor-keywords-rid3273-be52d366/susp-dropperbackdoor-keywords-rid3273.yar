rule SUSP_DropperBackdoor_Keywords_RID3273 : DEMO EXE FILE SUSP {
   meta:
      description = "Detects suspicious keywords that indicate a backdoor"
      author = "Florian Roth"
      reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
      date = "2019-04-24 14:05:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cd4b9d0f2d1c0468750855f0ed352c1ed6d4f512d66e0e44ce308688235295b5"
      tags = "DEMO, EXE, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x4 = "DropperBackdoor" fullword wide ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 1 of them
}