rule BlackEnergy_Driver_AMDIDE_RID3026 : APT DEMO EXE FILE blackenergy {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
      date = "2016-01-04 12:27:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "32d3121135a835c3347b553b70f3c4c68eef711af02c161f007a9fbaffe7e614"
      hash2 = "3432db9cb1fb9daa2f2ac554a0a006be96040d2a7776a072a8db051d064a8be2"
      hash3 = "90ba78b6710462c2d97815e8745679942b3b296135490f0095bdc0cd97a34d9c"
      tags = "APT, DEMO, EXE, FILE, blackenergy"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = " AMD IDE driver" fullword wide
      $s2 = "SessionEnv" fullword wide
      $s3 = "\\DosDevices\\{C9059FFF-1C49-4445-83E8-" wide
      $s4 = "\\Device\\{C9059FFF-1C49-4445-83E8-" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 150KB and all of them
}