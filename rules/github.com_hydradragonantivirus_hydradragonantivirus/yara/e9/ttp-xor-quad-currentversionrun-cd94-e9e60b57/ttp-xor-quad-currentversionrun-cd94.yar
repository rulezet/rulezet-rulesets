rule TTP_XOR_QUAD_CurrentVersionRun_cd94 {
  strings:
    $key_cd94 = { 9e fb [2] ba f5 [2] 91 d9 [2] bf fb [2] ab e0 [2] a4 fa [2] ba e7 [2] b8 e6 [2] a3 e0 [2] bf e7 [2] a3 c8 }

  condition:
    any of them
}