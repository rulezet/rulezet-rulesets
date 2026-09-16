rule EquationGroup_jparsescan {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jparsescan"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"
      id = "6b6a884e-0bbc-54f5-bb6c-00e15ca95250"
   strings:
      $s1 = "Usage:  $prog [-f directory] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
      $s2 = "$gotsunos = ($line =~ /program version netid     address             service         owner/ );" fullword ascii
   condition:
      ( filesize < 40KB and 1 of them )
}