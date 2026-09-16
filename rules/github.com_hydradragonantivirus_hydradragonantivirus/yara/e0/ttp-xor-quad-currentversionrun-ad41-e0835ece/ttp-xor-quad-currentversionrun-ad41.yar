rule TTP_XOR_QUAD_CurrentVersionRun_ad41 {
  strings:
    $key_ad41 = { fe 2e [2] da 20 [2] f1 0c [2] df 2e [2] cb 35 [2] c4 2f [2] da 32 [2] d8 33 [2] c3 35 [2] df 32 [2] c3 1d }

  condition:
    any of them
}