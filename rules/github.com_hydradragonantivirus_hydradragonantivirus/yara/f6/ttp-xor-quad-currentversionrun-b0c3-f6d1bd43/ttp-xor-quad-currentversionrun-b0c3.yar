rule TTP_XOR_QUAD_CurrentVersionRun_b0c3 {
  strings:
    $key_b0c3 = { e3 ac [2] c7 a2 [2] ec 8e [2] c2 ac [2] d6 b7 [2] d9 ad [2] c7 b0 [2] c5 b1 [2] de b7 [2] c2 b0 [2] de 9f }

  condition:
    any of them
}