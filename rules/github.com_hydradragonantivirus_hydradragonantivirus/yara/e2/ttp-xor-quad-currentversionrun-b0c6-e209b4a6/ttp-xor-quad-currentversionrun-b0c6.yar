rule TTP_XOR_QUAD_CurrentVersionRun_b0c6 {
  strings:
    $key_b0c6 = { e3 a9 [2] c7 a7 [2] ec 8b [2] c2 a9 [2] d6 b2 [2] d9 a8 [2] c7 b5 [2] c5 b4 [2] de b2 [2] c2 b5 [2] de 9a }

  condition:
    any of them
}