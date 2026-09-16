rule TTP_XOR_QUAD_CurrentVersionRun_c395 {
  strings:
    $key_c395 = { 90 fa [2] b4 f4 [2] 9f d8 [2] b1 fa [2] a5 e1 [2] aa fb [2] b4 e6 [2] b6 e7 [2] ad e1 [2] b1 e6 [2] ad c9 }

  condition:
    any of them
}