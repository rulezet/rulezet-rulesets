rule TTP_XOR_QUAD_CurrentVersionRun_78a8 {
  strings:
    $key_78a8 = { 2b c7 [2] 0f c9 [2] 24 e5 [2] 0a c7 [2] 1e dc [2] 11 c6 [2] 0f db [2] 0d da [2] 16 dc [2] 0a db [2] 16 f4 }

  condition:
    any of them
}