rule EquationGroup_packrat_RID2FA9 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file packrat"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:06:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d3e067879c51947d715fc2cf0d8d91c897fe9f50cae6784739b5c17e8a8559cf"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x2 = "Use this on target to get your RAT:" fullword ascii
      $x3 = "$ratremotename && " fullword ascii
      $x5 = "$command = \"$nc$bindto -vv -l -p $port < ${ratremotename}\" ;" fullword ascii
   condition: 
      ( filesize < 70KB and 1 of them )
}