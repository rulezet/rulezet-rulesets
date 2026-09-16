rule TTP_XOR_QUAD_CurrentVersionRun_adfb {
  strings:
    $key_adfb = { fe 94 [2] da 9a [2] f1 b6 [2] df 94 [2] cb 8f [2] c4 95 [2] da 88 [2] d8 89 [2] c3 8f [2] df 88 [2] c3 a7 }

  condition:
    any of them
}