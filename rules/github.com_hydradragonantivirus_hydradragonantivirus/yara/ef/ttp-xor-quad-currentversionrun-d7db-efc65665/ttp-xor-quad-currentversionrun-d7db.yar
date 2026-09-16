rule TTP_XOR_QUAD_CurrentVersionRun_d7db {
  strings:
    $key_d7db = { 84 b4 [2] a0 ba [2] 8b 96 [2] a5 b4 [2] b1 af [2] be b5 [2] a0 a8 [2] a2 a9 [2] b9 af [2] a5 a8 [2] b9 87 }

  condition:
    any of them
}