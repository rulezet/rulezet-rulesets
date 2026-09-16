rule TTP_XOR_QUAD_CurrentVersionRun_5ca8 {
  strings:
    $key_5ca8 = { 0f c7 [2] 2b c9 [2] 00 e5 [2] 2e c7 [2] 3a dc [2] 35 c6 [2] 2b db [2] 29 da [2] 32 dc [2] 2e db [2] 32 f4 }

  condition:
    any of them
}