rule PEiD_01851_PseudoSigner_0_1__WATCOM_C_C___EXE_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [WATCOM C/C++ EXE] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { E9 00 00 00 00 90 90 90 90 57 41 E9 }

  condition:
    $a
}