rule TTP_XOR_QUAD_CurrentVersionRun_b7aa {
  strings:
    $key_b7aa = { e4 c5 [2] c0 cb [2] eb e7 [2] c5 c5 [2] d1 de [2] de c4 [2] c0 d9 [2] c2 d8 [2] d9 de [2] c5 d9 [2] d9 f6 }

  condition:
    any of them
}