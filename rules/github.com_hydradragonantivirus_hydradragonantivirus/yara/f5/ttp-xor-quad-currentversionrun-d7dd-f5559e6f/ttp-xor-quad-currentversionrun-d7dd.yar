rule TTP_XOR_QUAD_CurrentVersionRun_d7dd {
  strings:
    $key_d7dd = { 84 b2 [2] a0 bc [2] 8b 90 [2] a5 b2 [2] b1 a9 [2] be b3 [2] a0 ae [2] a2 af [2] b9 a9 [2] a5 ae [2] b9 81 }

  condition:
    any of them
}