rule TTP_XOR_QUAD_CurrentVersionRun_ad14 {
  strings:
    $key_ad14 = { fe 7b [2] da 75 [2] f1 59 [2] df 7b [2] cb 60 [2] c4 7a [2] da 67 [2] d8 66 [2] c3 60 [2] df 67 [2] c3 48 }

  condition:
    any of them
}