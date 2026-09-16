rule TTP_XOR_QUAD_CurrentVersionRun_b7ba {
  strings:
    $key_b7ba = { e4 d5 [2] c0 db [2] eb f7 [2] c5 d5 [2] d1 ce [2] de d4 [2] c0 c9 [2] c2 c8 [2] d9 ce [2] c5 c9 [2] d9 e6 }

  condition:
    any of them
}