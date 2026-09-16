rule TTP_XOR_QUAD_CurrentVersionRun_6ab6 {
  strings:
    $key_6ab6 = { 39 d9 [2] 1d d7 [2] 36 fb [2] 18 d9 [2] 0c c2 [2] 03 d8 [2] 1d c5 [2] 1f c4 [2] 04 c2 [2] 18 c5 [2] 04 ea }

  condition:
    any of them
}