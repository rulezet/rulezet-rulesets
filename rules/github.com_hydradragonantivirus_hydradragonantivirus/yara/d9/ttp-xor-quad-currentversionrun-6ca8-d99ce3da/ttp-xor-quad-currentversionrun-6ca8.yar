rule TTP_XOR_QUAD_CurrentVersionRun_6ca8 {
  strings:
    $key_6ca8 = { 3f c7 [2] 1b c9 [2] 30 e5 [2] 1e c7 [2] 0a dc [2] 05 c6 [2] 1b db [2] 19 da [2] 02 dc [2] 1e db [2] 02 f4 }

  condition:
    any of them
}