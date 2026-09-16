rule TTP_XOR_QUAD_CurrentVersionRun_cedb {
  strings:
    $key_cedb = { 9d b4 [2] b9 ba [2] 92 96 [2] bc b4 [2] a8 af [2] a7 b5 [2] b9 a8 [2] bb a9 [2] a0 af [2] bc a8 [2] a0 87 }

  condition:
    any of them
}