rule TTP_XOR_QUAD_CurrentVersionRun_ad60 {
  strings:
    $key_ad60 = { fe 0f [2] da 01 [2] f1 2d [2] df 0f [2] cb 14 [2] c4 0e [2] da 13 [2] d8 12 [2] c3 14 [2] df 13 [2] c3 3c }

  condition:
    any of them
}