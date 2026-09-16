rule TTP_XOR_QUAD_CurrentVersionRun_ad40 {
  strings:
    $key_ad40 = { fe 2f [2] da 21 [2] f1 0d [2] df 2f [2] cb 34 [2] c4 2e [2] da 33 [2] d8 32 [2] c3 34 [2] df 33 [2] c3 1c }

  condition:
    any of them
}