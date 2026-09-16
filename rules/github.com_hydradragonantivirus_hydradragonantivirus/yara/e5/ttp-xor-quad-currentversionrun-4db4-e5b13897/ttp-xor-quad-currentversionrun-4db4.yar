rule TTP_XOR_QUAD_CurrentVersionRun_4db4 {
  strings:
    $key_4db4 = { 1e db [2] 3a d5 [2] 11 f9 [2] 3f db [2] 2b c0 [2] 24 da [2] 3a c7 [2] 38 c6 [2] 23 c0 [2] 3f c7 [2] 23 e8 }

  condition:
    any of them
}