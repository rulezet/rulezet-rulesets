rule TTP_XOR_QUAD_CurrentVersionRun_6d95 {
  strings:
    $key_6d95 = { 3e fa [2] 1a f4 [2] 31 d8 [2] 1f fa [2] 0b e1 [2] 04 fb [2] 1a e6 [2] 18 e7 [2] 03 e1 [2] 1f e6 [2] 03 c9 }

  condition:
    any of them
}