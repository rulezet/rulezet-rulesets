rule TTP_XOR_QUAD_CurrentVersionRun_d7c0 {
  strings:
    $key_d7c0 = { 84 af [2] a0 a1 [2] 8b 8d [2] a5 af [2] b1 b4 [2] be ae [2] a0 b3 [2] a2 b2 [2] b9 b4 [2] a5 b3 [2] b9 9c }

  condition:
    any of them
}