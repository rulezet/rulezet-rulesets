rule EquationGroup_jscan_RID2ED2 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jscan"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:30:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8075f56e44185e1be26b631a2bad89c5e4190c2bfc9fa56921ea3bbc51695dbe"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$scanth = $scanth . \" -s \" . $scanthreads;" fullword ascii
      $s2 = "print \"java -jar jscanner.jar$scanth$list\\n\";" fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}