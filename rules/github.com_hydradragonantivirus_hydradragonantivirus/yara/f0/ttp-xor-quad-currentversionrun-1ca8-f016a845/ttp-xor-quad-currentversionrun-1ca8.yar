rule TTP_XOR_QUAD_CurrentVersionRun_1ca8 {
  strings:
    $key_1ca8 = { 4f c7 [2] 6b c9 [2] 40 e5 [2] 6e c7 [2] 7a dc [2] 75 c6 [2] 6b db [2] 69 da [2] 72 dc [2] 6e db [2] 72 f4 }

  condition:
    any of them
}