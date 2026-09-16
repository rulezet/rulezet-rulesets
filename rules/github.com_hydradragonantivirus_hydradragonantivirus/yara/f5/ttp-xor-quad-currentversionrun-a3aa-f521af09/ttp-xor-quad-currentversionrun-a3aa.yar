rule TTP_XOR_QUAD_CurrentVersionRun_a3aa {
  strings:
    $key_a3aa = { f0 c5 [2] d4 cb [2] ff e7 [2] d1 c5 [2] c5 de [2] ca c4 [2] d4 d9 [2] d6 d8 [2] cd de [2] d1 d9 [2] cd f6 }

  condition:
    any of them
}