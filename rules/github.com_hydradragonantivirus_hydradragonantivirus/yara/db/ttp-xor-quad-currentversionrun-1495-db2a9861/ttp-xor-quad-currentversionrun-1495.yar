rule TTP_XOR_QUAD_CurrentVersionRun_1495 {
  strings:
    $key_1495 = { 47 fa [2] 63 f4 [2] 48 d8 [2] 66 fa [2] 72 e1 [2] 7d fb [2] 63 e6 [2] 61 e7 [2] 7a e1 [2] 66 e6 [2] 7a c9 }

  condition:
    any of them
}