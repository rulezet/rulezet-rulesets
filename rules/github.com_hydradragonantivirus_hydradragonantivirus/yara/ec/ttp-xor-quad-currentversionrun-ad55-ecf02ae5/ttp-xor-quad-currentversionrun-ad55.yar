rule TTP_XOR_QUAD_CurrentVersionRun_ad55 {
  strings:
    $key_ad55 = { fe 3a [2] da 34 [2] f1 18 [2] df 3a [2] cb 21 [2] c4 3b [2] da 26 [2] d8 27 [2] c3 21 [2] df 26 [2] c3 09 }

  condition:
    any of them
}