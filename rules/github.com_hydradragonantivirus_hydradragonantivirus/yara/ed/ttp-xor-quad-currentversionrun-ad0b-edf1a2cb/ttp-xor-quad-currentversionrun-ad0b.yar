rule TTP_XOR_QUAD_CurrentVersionRun_ad0b {
  strings:
    $key_ad0b = { fe 64 [2] da 6a [2] f1 46 [2] df 64 [2] cb 7f [2] c4 65 [2] da 78 [2] d8 79 [2] c3 7f [2] df 78 [2] c3 57 }

  condition:
    any of them
}