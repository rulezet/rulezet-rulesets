rule TTP_XOR_QUAD_CurrentVersionRun_ad13 {
  strings:
    $key_ad13 = { fe 7c [2] da 72 [2] f1 5e [2] df 7c [2] cb 67 [2] c4 7d [2] da 60 [2] d8 61 [2] c3 67 [2] df 60 [2] c3 4f }

  condition:
    any of them
}