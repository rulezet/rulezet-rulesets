rule TTP_XOR_QUAD_CurrentVersionRun_d2db {
  strings:
    $key_d2db = { 81 b4 [2] a5 ba [2] 8e 96 [2] a0 b4 [2] b4 af [2] bb b5 [2] a5 a8 [2] a7 a9 [2] bc af [2] a0 a8 [2] bc 87 }

  condition:
    any of them
}