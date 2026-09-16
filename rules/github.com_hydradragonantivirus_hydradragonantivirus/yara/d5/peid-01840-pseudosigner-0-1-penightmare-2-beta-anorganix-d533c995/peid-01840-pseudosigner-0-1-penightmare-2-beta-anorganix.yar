rule PEiD_01840_PseudoSigner_0_1__PENightMare_2_Beta_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [PENightMare 2 Beta] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A E9 }

  condition:
    $a
}