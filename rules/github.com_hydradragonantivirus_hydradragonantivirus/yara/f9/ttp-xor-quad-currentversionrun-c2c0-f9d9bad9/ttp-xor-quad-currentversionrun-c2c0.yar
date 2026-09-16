rule TTP_XOR_QUAD_CurrentVersionRun_c2c0 {
  strings:
    $key_c2c0 = { 91 af [2] b5 a1 [2] 9e 8d [2] b0 af [2] a4 b4 [2] ab ae [2] b5 b3 [2] b7 b2 [2] ac b4 [2] b0 b3 [2] ac 9c }

  condition:
    any of them
}