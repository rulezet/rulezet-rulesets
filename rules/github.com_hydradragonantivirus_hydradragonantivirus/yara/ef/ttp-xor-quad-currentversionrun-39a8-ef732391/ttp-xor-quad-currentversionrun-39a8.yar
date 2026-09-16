rule TTP_XOR_QUAD_CurrentVersionRun_39a8 {
  strings:
    $key_39a8 = { 6a c7 [2] 4e c9 [2] 65 e5 [2] 4b c7 [2] 5f dc [2] 50 c6 [2] 4e db [2] 4c da [2] 57 dc [2] 4b db [2] 57 f4 }

  condition:
    any of them
}