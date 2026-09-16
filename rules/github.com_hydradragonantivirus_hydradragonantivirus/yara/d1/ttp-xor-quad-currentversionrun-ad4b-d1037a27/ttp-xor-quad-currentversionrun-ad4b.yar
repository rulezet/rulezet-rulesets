rule TTP_XOR_QUAD_CurrentVersionRun_ad4b {
  strings:
    $key_ad4b = { fe 24 [2] da 2a [2] f1 06 [2] df 24 [2] cb 3f [2] c4 25 [2] da 38 [2] d8 39 [2] c3 3f [2] df 38 [2] c3 17 }

  condition:
    any of them
}