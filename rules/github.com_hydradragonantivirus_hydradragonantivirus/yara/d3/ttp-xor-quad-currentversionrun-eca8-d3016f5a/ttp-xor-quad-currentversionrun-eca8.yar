rule TTP_XOR_QUAD_CurrentVersionRun_eca8 {
  strings:
    $key_eca8 = { bf c7 [2] 9b c9 [2] b0 e5 [2] 9e c7 [2] 8a dc [2] 85 c6 [2] 9b db [2] 99 da [2] 82 dc [2] 9e db [2] 82 f4 }

  condition:
    any of them
}