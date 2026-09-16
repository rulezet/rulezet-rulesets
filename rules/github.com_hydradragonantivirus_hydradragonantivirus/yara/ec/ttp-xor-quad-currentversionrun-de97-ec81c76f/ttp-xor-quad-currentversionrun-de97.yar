rule TTP_XOR_QUAD_CurrentVersionRun_de97 {
  strings:
    $key_de97 = { 8d f8 [2] a9 f6 [2] 82 da [2] ac f8 [2] b8 e3 [2] b7 f9 [2] a9 e4 [2] ab e5 [2] b0 e3 [2] ac e4 [2] b0 cb }

  condition:
    any of them
}