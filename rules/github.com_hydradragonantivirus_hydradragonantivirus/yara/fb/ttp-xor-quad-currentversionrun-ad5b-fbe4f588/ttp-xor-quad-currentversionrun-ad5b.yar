rule TTP_XOR_QUAD_CurrentVersionRun_ad5b {
  strings:
    $key_ad5b = { fe 34 [2] da 3a [2] f1 16 [2] df 34 [2] cb 2f [2] c4 35 [2] da 28 [2] d8 29 [2] c3 2f [2] df 28 [2] c3 07 }

  condition:
    any of them
}