rule TTP_XOR_QUAD_CurrentVersionRun_d4c0 {
  strings:
    $key_d4c0 = { 87 af [2] a3 a1 [2] 88 8d [2] a6 af [2] b2 b4 [2] bd ae [2] a3 b3 [2] a1 b2 [2] ba b4 [2] a6 b3 [2] ba 9c }

  condition:
    any of them
}