rule TTP_XOR_QUAD_CurrentVersionRun_b6d1 {
  strings:
    $key_b6d1 = { e5 be [2] c1 b0 [2] ea 9c [2] c4 be [2] d0 a5 [2] df bf [2] c1 a2 [2] c3 a3 [2] d8 a5 [2] c4 a2 [2] d8 8d }

  condition:
    any of them
}