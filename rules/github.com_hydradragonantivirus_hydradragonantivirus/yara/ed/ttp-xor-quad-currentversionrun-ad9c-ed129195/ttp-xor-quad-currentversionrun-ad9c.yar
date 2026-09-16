rule TTP_XOR_QUAD_CurrentVersionRun_ad9c {
  strings:
    $key_ad9c = { fe f3 [2] da fd [2] f1 d1 [2] df f3 [2] cb e8 [2] c4 f2 [2] da ef [2] d8 ee [2] c3 e8 [2] df ef [2] c3 c0 }

  condition:
    any of them
}