rule TTP_XOR_QUAD_CurrentVersionRun_d485 {
  strings:
    $key_d485 = { 87 ea [2] a3 e4 [2] 88 c8 [2] a6 ea [2] b2 f1 [2] bd eb [2] a3 f6 [2] a1 f7 [2] ba f1 [2] a6 f6 [2] ba d9 }

  condition:
    any of them
}