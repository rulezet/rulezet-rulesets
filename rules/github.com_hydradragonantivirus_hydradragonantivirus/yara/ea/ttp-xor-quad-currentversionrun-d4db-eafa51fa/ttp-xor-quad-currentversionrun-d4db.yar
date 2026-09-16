rule TTP_XOR_QUAD_CurrentVersionRun_d4db {
  strings:
    $key_d4db = { 87 b4 [2] a3 ba [2] 88 96 [2] a6 b4 [2] b2 af [2] bd b5 [2] a3 a8 [2] a1 a9 [2] ba af [2] a6 a8 [2] ba 87 }

  condition:
    any of them
}