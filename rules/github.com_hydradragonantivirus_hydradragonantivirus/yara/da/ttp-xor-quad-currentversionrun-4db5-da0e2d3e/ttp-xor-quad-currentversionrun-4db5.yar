rule TTP_XOR_QUAD_CurrentVersionRun_4db5 {
  strings:
    $key_4db5 = { 1e da [2] 3a d4 [2] 11 f8 [2] 3f da [2] 2b c1 [2] 24 db [2] 3a c6 [2] 38 c7 [2] 23 c1 [2] 3f c6 [2] 23 e9 }

  condition:
    any of them
}