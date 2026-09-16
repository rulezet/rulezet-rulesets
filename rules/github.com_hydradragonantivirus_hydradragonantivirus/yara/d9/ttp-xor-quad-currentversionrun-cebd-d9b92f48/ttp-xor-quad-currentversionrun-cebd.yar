rule TTP_XOR_QUAD_CurrentVersionRun_cebd {
  strings:
    $key_cebd = { 9d d2 [2] b9 dc [2] 92 f0 [2] bc d2 [2] a8 c9 [2] a7 d3 [2] b9 ce [2] bb cf [2] a0 c9 [2] bc ce [2] a0 e1 }

  condition:
    any of them
}