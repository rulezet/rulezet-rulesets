rule TTP_XOR_QUAD_CurrentVersionRun_b0e9 {
  strings:
    $key_b0e9 = { e3 86 [2] c7 88 [2] ec a4 [2] c2 86 [2] d6 9d [2] d9 87 [2] c7 9a [2] c5 9b [2] de 9d [2] c2 9a [2] de b5 }

  condition:
    any of them
}