rule TTP_XOR_QUAD_CurrentVersionRun_ee9c {
  strings:
    $key_ee9c = { bd f3 [2] 99 fd [2] b2 d1 [2] 9c f3 [2] 88 e8 [2] 87 f2 [2] 99 ef [2] 9b ee [2] 80 e8 [2] 9c ef [2] 80 c0 }

  condition:
    any of them
}