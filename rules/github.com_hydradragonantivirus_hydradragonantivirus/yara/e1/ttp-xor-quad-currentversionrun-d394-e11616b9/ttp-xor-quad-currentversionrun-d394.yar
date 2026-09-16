rule TTP_XOR_QUAD_CurrentVersionRun_d394 {
  strings:
    $key_d394 = { 80 fb [2] a4 f5 [2] 8f d9 [2] a1 fb [2] b5 e0 [2] ba fa [2] a4 e7 [2] a6 e6 [2] bd e0 [2] a1 e7 [2] bd c8 }

  condition:
    any of them
}