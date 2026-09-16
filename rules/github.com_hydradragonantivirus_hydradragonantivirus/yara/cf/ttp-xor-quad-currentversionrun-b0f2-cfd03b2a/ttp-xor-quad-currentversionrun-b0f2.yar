rule TTP_XOR_QUAD_CurrentVersionRun_b0f2 {
  strings:
    $key_b0f2 = { e3 9d [2] c7 93 [2] ec bf [2] c2 9d [2] d6 86 [2] d9 9c [2] c7 81 [2] c5 80 [2] de 86 [2] c2 81 [2] de ae }

  condition:
    any of them
}