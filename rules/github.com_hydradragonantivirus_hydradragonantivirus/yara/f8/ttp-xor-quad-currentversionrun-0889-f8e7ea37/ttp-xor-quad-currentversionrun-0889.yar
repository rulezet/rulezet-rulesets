rule TTP_XOR_QUAD_CurrentVersionRun_0889 {
  strings:
    $key_0889 = { 5b e6 [2] 7f e8 [2] 54 c4 [2] 7a e6 [2] 6e fd [2] 61 e7 [2] 7f fa [2] 7d fb [2] 66 fd [2] 7a fa [2] 66 d5 }

  condition:
    any of them
}