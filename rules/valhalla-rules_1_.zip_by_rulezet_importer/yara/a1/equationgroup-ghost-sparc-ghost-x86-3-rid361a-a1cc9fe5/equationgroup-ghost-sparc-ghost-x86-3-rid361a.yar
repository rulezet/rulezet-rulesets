rule EquationGroup__ghost_sparc_ghost_x86_3_RID361A : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files ghost_sparc, ghost_x86"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 16:41:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d5ff0208d9532fc0c6716bd57297397c8151a01bf4f21311f24e7a72551f9bf1"
      hash2 = "82c899d1f05b50a85646a782cddb774d194ef85b74e1be642a8be2c7119f4e33"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Usage: %s [-v os] [-p] [-r] [-c command] [-a attacker] target" fullword ascii
      $x2 = "Sending shellcode as part of an open command..." fullword ascii
      $x3 = "cmdshellcode" fullword ascii
      $x4 = "You will not be able to run the shellcode. Exiting..." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 70KB and 1 of them ) or ( 2 of them )
}