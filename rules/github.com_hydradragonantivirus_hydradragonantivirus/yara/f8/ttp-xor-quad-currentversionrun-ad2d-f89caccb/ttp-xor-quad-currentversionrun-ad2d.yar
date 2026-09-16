rule TTP_XOR_QUAD_CurrentVersionRun_ad2d {
  strings:
    $key_ad2d = { fe 42 [2] da 4c [2] f1 60 [2] df 42 [2] cb 59 [2] c4 43 [2] da 5e [2] d8 5f [2] c3 59 [2] df 5e [2] c3 71 }

  condition:
    any of them
}