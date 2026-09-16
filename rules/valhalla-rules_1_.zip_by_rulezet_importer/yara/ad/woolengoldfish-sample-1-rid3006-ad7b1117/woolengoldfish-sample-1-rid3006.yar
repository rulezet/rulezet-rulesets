rule WoolenGoldfish_Sample_1_RID3006 : APT DEMO G0130 {
   meta:
      description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
      author = "Florian Roth"
      reference = "http://goo.gl/NpJpVZ"
      date = "2015-03-25 12:22:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, G0130"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Cannot execute (%d)" fullword ascii
      $s16 = "SvcName" fullword ascii
   condition: 
      all of them
}