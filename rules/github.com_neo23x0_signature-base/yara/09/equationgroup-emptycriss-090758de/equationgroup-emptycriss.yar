rule EquationGroup_emptycriss {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file emptycriss"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a698d35a0c4d25fd960bd40c1de1022bb0763b77938bf279e91c9330060b0b91"
      id = "658a0a2c-ea3a-5531-abea-54f0ed786e79"
   strings:
      $s1 = "./emptycriss <target IP>" fullword ascii
      $s2 = "Cut and paste the following to the telnet prompt:" fullword ascii
      $s8 = "environ define TTYPROMPT abcdef" fullword ascii
   condition:
      ( filesize < 50KB and 1 of them )
}