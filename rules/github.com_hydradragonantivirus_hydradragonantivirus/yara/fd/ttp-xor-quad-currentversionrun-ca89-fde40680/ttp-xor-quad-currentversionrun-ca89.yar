rule TTP_XOR_QUAD_CurrentVersionRun_ca89 {
  strings:
    $key_ca89 = { 99 e6 [2] bd e8 [2] 96 c4 [2] b8 e6 [2] ac fd [2] a3 e7 [2] bd fa [2] bf fb [2] a4 fd [2] b8 fa [2] a4 d5 }

  condition:
    any of them
}