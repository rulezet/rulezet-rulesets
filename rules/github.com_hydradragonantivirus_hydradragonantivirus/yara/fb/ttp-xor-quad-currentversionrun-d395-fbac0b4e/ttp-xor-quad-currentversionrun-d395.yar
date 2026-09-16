rule TTP_XOR_QUAD_CurrentVersionRun_d395 {
  strings:
    $key_d395 = { 80 fa [2] a4 f4 [2] 8f d8 [2] a1 fa [2] b5 e1 [2] ba fb [2] a4 e6 [2] a6 e7 [2] bd e1 [2] a1 e6 [2] bd c9 }

  condition:
    any of them
}