rule EquationGroup_cursezinger_linuxrh7_3_v_2_0_0_RID382A : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 18:09:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "af7c7d03f59460fa60c48764201e18f3bd3f72441fd2e2ff6a562291134d2135"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ",%02d%03d" fullword ascii
      $s2 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
      $s3 = "__strtoll_internal" ascii
      $s4 = "__strtoul_internal" ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 400KB and all of them )
}