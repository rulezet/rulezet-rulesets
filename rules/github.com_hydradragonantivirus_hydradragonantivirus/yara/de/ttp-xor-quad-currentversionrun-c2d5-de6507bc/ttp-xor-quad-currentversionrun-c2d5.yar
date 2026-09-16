rule TTP_XOR_QUAD_CurrentVersionRun_c2d5 {
  strings:
    $key_c2d5 = { 91 ba [2] b5 b4 [2] 9e 98 [2] b0 ba [2] a4 a1 [2] ab bb [2] b5 a6 [2] b7 a7 [2] ac a1 [2] b0 a6 [2] ac 89 }

  condition:
    any of them
}