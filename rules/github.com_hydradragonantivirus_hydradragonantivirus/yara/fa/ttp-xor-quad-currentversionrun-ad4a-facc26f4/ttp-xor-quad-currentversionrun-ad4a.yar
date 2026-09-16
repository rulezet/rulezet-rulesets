rule TTP_XOR_QUAD_CurrentVersionRun_ad4a {
  strings:
    $key_ad4a = { fe 25 [2] da 2b [2] f1 07 [2] df 25 [2] cb 3e [2] c4 24 [2] da 39 [2] d8 38 [2] c3 3e [2] df 39 [2] c3 16 }

  condition:
    any of them
}