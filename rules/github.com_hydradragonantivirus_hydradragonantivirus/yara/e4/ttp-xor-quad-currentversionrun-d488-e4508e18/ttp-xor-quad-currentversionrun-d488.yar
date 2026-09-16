rule TTP_XOR_QUAD_CurrentVersionRun_d488 {
  strings:
    $key_d488 = { 87 e7 [2] a3 e9 [2] 88 c5 [2] a6 e7 [2] b2 fc [2] bd e6 [2] a3 fb [2] a1 fa [2] ba fc [2] a6 fb [2] ba d4 }

  condition:
    any of them
}