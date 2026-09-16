rule TTP_XOR_QUAD_CurrentVersionRun_b8a5 {
  strings:
    $key_b8a5 = { eb ca [2] cf c4 [2] e4 e8 [2] ca ca [2] de d1 [2] d1 cb [2] cf d6 [2] cd d7 [2] d6 d1 [2] ca d6 [2] d6 f9 }

  condition:
    any of them
}