rule TTP_XOR_QUAD_CurrentVersionRun_d4c1 {
  strings:
    $key_d4c1 = { 87 ae [2] a3 a0 [2] 88 8c [2] a6 ae [2] b2 b5 [2] bd af [2] a3 b2 [2] a1 b3 [2] ba b5 [2] a6 b2 [2] ba 9d }

  condition:
    any of them
}