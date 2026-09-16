rule EquationGroup_cursetingle_2_0_1_2_mswin32_v_2_0_1_RID3920 : APT DEMO EXE FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 18:50:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "614bf159b956f20d66cedf25af7503b41e91841c75707af0cdf4495084092a61"
      tags = "APT, DEMO, EXE, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
      $s2 = "0123456789abcdefABCEDF:" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}