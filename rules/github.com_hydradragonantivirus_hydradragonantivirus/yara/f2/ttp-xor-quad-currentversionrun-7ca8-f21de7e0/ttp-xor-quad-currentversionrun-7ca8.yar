rule TTP_XOR_QUAD_CurrentVersionRun_7ca8 {
  strings:
    $key_7ca8 = { 2f c7 [2] 0b c9 [2] 20 e5 [2] 0e c7 [2] 1a dc [2] 15 c6 [2] 0b db [2] 09 da [2] 12 dc [2] 0e db [2] 12 f4 }

  condition:
    any of them
}