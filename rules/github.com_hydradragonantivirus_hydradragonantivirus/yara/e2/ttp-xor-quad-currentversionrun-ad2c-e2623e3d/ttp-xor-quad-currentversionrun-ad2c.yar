rule TTP_XOR_QUAD_CurrentVersionRun_ad2c {
  strings:
    $key_ad2c = { fe 43 [2] da 4d [2] f1 61 [2] df 43 [2] cb 58 [2] c4 42 [2] da 5f [2] d8 5e [2] c3 58 [2] df 5f [2] c3 70 }

  condition:
    any of them
}