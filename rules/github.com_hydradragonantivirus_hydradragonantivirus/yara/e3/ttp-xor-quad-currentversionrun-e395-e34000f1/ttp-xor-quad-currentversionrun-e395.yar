rule TTP_XOR_QUAD_CurrentVersionRun_e395 {
  strings:
    $key_e395 = { b0 fa [2] 94 f4 [2] bf d8 [2] 91 fa [2] 85 e1 [2] 8a fb [2] 94 e6 [2] 96 e7 [2] 8d e1 [2] 91 e6 [2] 8d c9 }

  condition:
    any of them
}