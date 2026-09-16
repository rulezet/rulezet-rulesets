rule PEiD_01886_PseudoSigner_0_2__PENightMare_2_Beta__ {
  meta:
    description = "[PseudoSigner 0.2 [PENightMare 2 Beta]]"
    ep_only     = "true"

  strings:
    $a = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }

  condition:
    $a
}