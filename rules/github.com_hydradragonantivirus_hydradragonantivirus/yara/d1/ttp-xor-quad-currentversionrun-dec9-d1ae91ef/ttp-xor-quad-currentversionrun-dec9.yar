rule TTP_XOR_QUAD_CurrentVersionRun_dec9 {
  strings:
    $key_dec9 = { 8d a6 [2] a9 a8 [2] 82 84 [2] ac a6 [2] b8 bd [2] b7 a7 [2] a9 ba [2] ab bb [2] b0 bd [2] ac ba [2] b0 95 }

  condition:
    any of them
}