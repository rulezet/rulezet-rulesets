rule TTP_XOR_QUAD_CurrentVersionRun_28a8 {
  strings:
    $key_28a8 = { 7b c7 [2] 5f c9 [2] 74 e5 [2] 5a c7 [2] 4e dc [2] 41 c6 [2] 5f db [2] 5d da [2] 46 dc [2] 5a db [2] 46 f4 }

  condition:
    any of them
}