rule EquationGroup_emptycriss_RID3116 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file emptycriss"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:07:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a698d35a0c4d25fd960bd40c1de1022bb0763b77938bf279e91c9330060b0b91"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "./emptycriss <target IP>" fullword ascii
      $s2 = "Cut and paste the following to the telnet prompt:" fullword ascii
      $s8 = "environ define TTYPROMPT abcdef" fullword ascii
   condition: 
      ( filesize < 50KB and 1 of them )
}