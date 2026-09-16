rule TTP_XOR_QUAD_CurrentVersionRun_ad19 {
  strings:
    $key_ad19 = { fe 76 [2] da 78 [2] f1 54 [2] df 76 [2] cb 6d [2] c4 77 [2] da 6a [2] d8 6b [2] c3 6d [2] df 6a [2] c3 45 }

  condition:
    any of them
}