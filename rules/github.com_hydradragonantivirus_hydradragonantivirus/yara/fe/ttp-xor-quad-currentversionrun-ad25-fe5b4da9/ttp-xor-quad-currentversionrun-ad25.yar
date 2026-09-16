rule TTP_XOR_QUAD_CurrentVersionRun_ad25 {
  strings:
    $key_ad25 = { fe 4a [2] da 44 [2] f1 68 [2] df 4a [2] cb 51 [2] c4 4b [2] da 56 [2] d8 57 [2] c3 51 [2] df 56 [2] c3 79 }

  condition:
    any of them
}