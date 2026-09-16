rule EquationGroup_jscan {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jscan"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "8075f56e44185e1be26b631a2bad89c5e4190c2bfc9fa56921ea3bbc51695dbe"
      id = "c4cebc69-8ec8-5ad7-bd93-55565b3eb92b"
   strings:
      $s1 = "$scanth = $scanth . \" -s \" . $scanthreads;" fullword ascii
      $s2 = "print \"java -jar jscanner.jar$scanth$list\\n\";" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}