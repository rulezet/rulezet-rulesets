rule EquationGroup_elgingamble {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file elgingamble"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "0573e12632e6c1925358f4bfecf8c263dd13edf52c633c9109fe3aae059b49dd"
      id = "fc8a63a1-9deb-5051-a02d-ed26fd1cae95"
   strings:
      $x1 = "* * * * * root chown root %s; chmod 4755 %s; %s" fullword ascii
      $x2 = "[-] kernel not vulnerable" fullword ascii
      $x3 = "[-] failed to spawn shell: %s" fullword ascii
      $x4 = "-s shell           Use shell instead of %s" fullword ascii
   condition:
      1 of them
}