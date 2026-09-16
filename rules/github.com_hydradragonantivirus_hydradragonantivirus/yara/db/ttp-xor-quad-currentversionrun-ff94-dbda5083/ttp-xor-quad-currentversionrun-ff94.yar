rule TTP_XOR_QUAD_CurrentVersionRun_ff94 {
  strings:
    $key_ff94 = { ac fb [2] 88 f5 [2] a3 d9 [2] 8d fb [2] 99 e0 [2] 96 fa [2] 88 e7 [2] 8a e6 [2] 91 e0 [2] 8d e7 [2] 91 c8 }

  condition:
    any of them
}