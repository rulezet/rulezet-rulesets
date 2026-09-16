rule EquationGroup_parsescan {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file parsescan"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "942c12067b0afe9ebce50aa9dfdbf64e6ed0702d9a3a00d25b4fca62a38369ef"
      id = "bbe8b518-2bf0-5de4-8fb8-9b8609d393dc"
   strings:
      $s1 = "$gotgs=1 if (($line =~ /Scan for (Sol|SNMP)\\s+version/) or" fullword ascii
      $s2 = "Usage:  $prog [-f file] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}