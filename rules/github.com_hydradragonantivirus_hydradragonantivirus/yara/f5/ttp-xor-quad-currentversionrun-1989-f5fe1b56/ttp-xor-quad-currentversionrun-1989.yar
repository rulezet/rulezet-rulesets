rule TTP_XOR_QUAD_CurrentVersionRun_1989 {
  strings:
    $key_1989 = { 4a e6 [2] 6e e8 [2] 45 c4 [2] 6b e6 [2] 7f fd [2] 70 e7 [2] 6e fa [2] 6c fb [2] 77 fd [2] 6b fa [2] 77 d5 }

  condition:
    any of them
}