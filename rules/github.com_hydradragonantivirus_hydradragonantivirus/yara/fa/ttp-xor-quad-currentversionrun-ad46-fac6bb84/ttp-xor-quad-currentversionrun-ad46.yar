rule TTP_XOR_QUAD_CurrentVersionRun_ad46 {
  strings:
    $key_ad46 = { fe 29 [2] da 27 [2] f1 0b [2] df 29 [2] cb 32 [2] c4 28 [2] da 35 [2] d8 34 [2] c3 32 [2] df 35 [2] c3 1a }

  condition:
    any of them
}