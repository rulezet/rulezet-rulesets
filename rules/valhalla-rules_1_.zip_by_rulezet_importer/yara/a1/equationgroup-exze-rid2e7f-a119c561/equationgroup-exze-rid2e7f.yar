rule EquationGroup_exze_RID2E7F : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file exze"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:17:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1af6dde6d956db26c8072bf5ff26759f1a7fa792dd1c3498ba1af06426664876"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "shellFile" fullword ascii
      $s2 = "completed.1" fullword ascii
      $s3 = "zeke_remove" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 80KB and all of them )
}