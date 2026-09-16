rule TTP_XOR_QUAD_CurrentVersionRun_ade5 {
  strings:
    $key_ade5 = { fe 8a [2] da 84 [2] f1 a8 [2] df 8a [2] cb 91 [2] c4 8b [2] da 96 [2] d8 97 [2] c3 91 [2] df 96 [2] c3 b9 }

  condition:
    any of them
}