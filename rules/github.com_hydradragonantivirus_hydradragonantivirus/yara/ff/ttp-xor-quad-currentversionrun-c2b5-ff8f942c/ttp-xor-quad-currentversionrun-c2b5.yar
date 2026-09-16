rule TTP_XOR_QUAD_CurrentVersionRun_c2b5 {
  strings:
    $key_c2b5 = { 91 da [2] b5 d4 [2] 9e f8 [2] b0 da [2] a4 c1 [2] ab db [2] b5 c6 [2] b7 c7 [2] ac c1 [2] b0 c6 [2] ac e9 }

  condition:
    any of them
}