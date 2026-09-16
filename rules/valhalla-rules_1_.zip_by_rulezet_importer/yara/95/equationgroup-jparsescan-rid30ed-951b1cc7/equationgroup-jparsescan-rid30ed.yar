rule EquationGroup_jparsescan_RID30ED : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jparsescan"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage:  $prog [-f directory] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
      $s2 = "$gotsunos = ($line =~ /program version netid     address             service         owner/ );" fullword ascii
   condition: 
      ( filesize < 40KB and 1 of them )
}