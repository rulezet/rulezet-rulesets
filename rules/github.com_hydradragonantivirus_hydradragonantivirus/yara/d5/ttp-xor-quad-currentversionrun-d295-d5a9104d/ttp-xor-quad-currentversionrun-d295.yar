rule TTP_XOR_QUAD_CurrentVersionRun_d295 {
  strings:
    $key_d295 = { 81 fa [2] a5 f4 [2] 8e d8 [2] a0 fa [2] b4 e1 [2] bb fb [2] a5 e6 [2] a7 e7 [2] bc e1 [2] a0 e6 [2] bc c9 }

  condition:
    any of them
}