rule TTP_XOR_QUAD_CurrentVersionRun_ad4c {
  strings:
    $key_ad4c = { fe 23 [2] da 2d [2] f1 01 [2] df 23 [2] cb 38 [2] c4 22 [2] da 3f [2] d8 3e [2] c3 38 [2] df 3f [2] c3 10 }

  condition:
    any of them
}