rule TTP_XOR_QUAD_CurrentVersionRun_b709 {
  strings:
    $key_b709 = { e4 66 [2] c0 68 [2] eb 44 [2] c5 66 [2] d1 7d [2] de 67 [2] c0 7a [2] c2 7b [2] d9 7d [2] c5 7a [2] d9 55 }

  condition:
    any of them
}