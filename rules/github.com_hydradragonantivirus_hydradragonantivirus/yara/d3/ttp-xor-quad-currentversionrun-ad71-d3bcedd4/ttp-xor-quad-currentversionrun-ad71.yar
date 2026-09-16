rule TTP_XOR_QUAD_CurrentVersionRun_ad71 {
  strings:
    $key_ad71 = { fe 1e [2] da 10 [2] f1 3c [2] df 1e [2] cb 05 [2] c4 1f [2] da 02 [2] d8 03 [2] c3 05 [2] df 02 [2] c3 2d }

  condition:
    any of them
}