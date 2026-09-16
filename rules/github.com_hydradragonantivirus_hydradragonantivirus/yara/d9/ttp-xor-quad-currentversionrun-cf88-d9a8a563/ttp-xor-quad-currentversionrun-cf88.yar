rule TTP_XOR_QUAD_CurrentVersionRun_cf88 {
  strings:
    $key_cf88 = { 9c e7 [2] b8 e9 [2] 93 c5 [2] bd e7 [2] a9 fc [2] a6 e6 [2] b8 fb [2] ba fa [2] a1 fc [2] bd fb [2] a1 d4 }

  condition:
    any of them
}