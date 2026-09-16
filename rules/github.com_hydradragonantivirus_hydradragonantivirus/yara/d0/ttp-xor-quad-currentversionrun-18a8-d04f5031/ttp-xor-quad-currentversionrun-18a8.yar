rule TTP_XOR_QUAD_CurrentVersionRun_18a8 {
  strings:
    $key_18a8 = { 4b c7 [2] 6f c9 [2] 44 e5 [2] 6a c7 [2] 7e dc [2] 71 c6 [2] 6f db [2] 6d da [2] 76 dc [2] 6a db [2] 76 f4 }

  condition:
    any of them
}