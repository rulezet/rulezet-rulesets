rule TTP_XOR_QUAD_CurrentVersionRun_cfc0 {
  strings:
    $key_cfc0 = { 9c af [2] b8 a1 [2] 93 8d [2] bd af [2] a9 b4 [2] a6 ae [2] b8 b3 [2] ba b2 [2] a1 b4 [2] bd b3 [2] a1 9c }

  condition:
    any of them
}