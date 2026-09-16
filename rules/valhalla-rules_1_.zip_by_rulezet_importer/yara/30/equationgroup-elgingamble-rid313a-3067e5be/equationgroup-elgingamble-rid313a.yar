rule EquationGroup_elgingamble_RID313A : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file elgingamble"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:13:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0573e12632e6c1925358f4bfecf8c263dd13edf52c633c9109fe3aae059b49dd"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "* * * * * root chown root %s; chmod 4755 %s; %s" fullword ascii
      $x2 = "[-] kernel not vulnerable" fullword ascii
      $x3 = "[-] failed to spawn shell: %s" fullword ascii
      $x4 = "-s shell           Use shell instead of %s" fullword ascii
   condition: 
      1 of them
}