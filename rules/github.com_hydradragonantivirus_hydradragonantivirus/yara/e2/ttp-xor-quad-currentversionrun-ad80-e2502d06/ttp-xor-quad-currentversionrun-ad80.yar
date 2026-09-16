rule TTP_XOR_QUAD_CurrentVersionRun_ad80 {
  strings:
    $key_ad80 = { fe ef [2] da e1 [2] f1 cd [2] df ef [2] cb f4 [2] c4 ee [2] da f3 [2] d8 f2 [2] c3 f4 [2] df f3 [2] c3 dc }

  condition:
    any of them
}