rule TTP_XOR_QUAD_CurrentVersionRun_c587 {
  strings:
    $key_c587 = { 96 e8 [2] b2 e6 [2] 99 ca [2] b7 e8 [2] a3 f3 [2] ac e9 [2] b2 f4 [2] b0 f5 [2] ab f3 [2] b7 f4 [2] ab db }

  condition:
    any of them
}