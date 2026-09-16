rule Molerats_Jul17_Sample_Dropper_RID3246 : APT DEMO EXE FILE G0021 {
   meta:
      description = "Detects Molerats sample dropper SFX - July 2017"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07 13:58:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ad0b3ac8c573d84c0862bf1c912dba951ec280d31fe5b84745ccd12164b0bcdb"
      tags = "APT, DEMO, EXE, FILE, G0021"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Please remove %s from %s folder. It is unsecure to run %s until it is done." fullword wide
      $s2 = "sfxrar.exe" fullword ascii
      $s3 = "attachment.hta" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}