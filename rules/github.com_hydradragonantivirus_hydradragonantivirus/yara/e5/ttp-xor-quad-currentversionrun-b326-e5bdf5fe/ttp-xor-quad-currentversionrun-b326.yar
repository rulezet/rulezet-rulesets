rule TTP_XOR_QUAD_CurrentVersionRun_b326 {
  strings:
    $key_b326 = { e0 49 [2] c4 47 [2] ef 6b [2] c1 49 [2] d5 52 [2] da 48 [2] c4 55 [2] c6 54 [2] dd 52 [2] c1 55 [2] dd 7a }

  condition:
    any of them
}