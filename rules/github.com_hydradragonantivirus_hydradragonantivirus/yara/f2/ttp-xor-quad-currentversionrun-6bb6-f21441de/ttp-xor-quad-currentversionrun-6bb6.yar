rule TTP_XOR_QUAD_CurrentVersionRun_6bb6 {
  strings:
    $key_6bb6 = { 38 d9 [2] 1c d7 [2] 37 fb [2] 19 d9 [2] 0d c2 [2] 02 d8 [2] 1c c5 [2] 1e c4 [2] 05 c2 [2] 19 c5 [2] 05 ea }

  condition:
    any of them
}