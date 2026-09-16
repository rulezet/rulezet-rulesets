rule TTP_XOR_QUAD_CurrentVersionRun_71b6 {
  strings:
    $key_71b6 = { 22 d9 [2] 06 d7 [2] 2d fb [2] 03 d9 [2] 17 c2 [2] 18 d8 [2] 06 c5 [2] 04 c4 [2] 1f c2 [2] 03 c5 [2] 1f ea }

  condition:
    any of them
}