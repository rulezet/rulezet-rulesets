rule PEiD_01890_PseudoSigner_0_2__UPX_0_6__ {
  meta:
    description = "[PseudoSigner 0.2 [UPX 0.6]]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }

  condition:
    $a
}