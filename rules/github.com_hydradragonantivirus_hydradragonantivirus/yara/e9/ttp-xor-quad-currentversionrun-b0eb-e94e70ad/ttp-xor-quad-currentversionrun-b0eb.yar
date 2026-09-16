rule TTP_XOR_QUAD_CurrentVersionRun_b0eb {
  strings:
    $key_b0eb = { e3 84 [2] c7 8a [2] ec a6 [2] c2 84 [2] d6 9f [2] d9 85 [2] c7 98 [2] c5 99 [2] de 9f [2] c2 98 [2] de b7 }

  condition:
    any of them
}