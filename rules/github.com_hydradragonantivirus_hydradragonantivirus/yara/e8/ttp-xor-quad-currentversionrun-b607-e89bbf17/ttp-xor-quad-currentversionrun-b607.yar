rule TTP_XOR_QUAD_CurrentVersionRun_b607 {
  strings:
    $key_b607 = { e5 68 [2] c1 66 [2] ea 4a [2] c4 68 [2] d0 73 [2] df 69 [2] c1 74 [2] c3 75 [2] d8 73 [2] c4 74 [2] d8 5b }

  condition:
    any of them
}