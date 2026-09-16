rule TTP_XOR_QUAD_CurrentVersionRun_aded {
  strings:
    $key_aded = { fe 82 [2] da 8c [2] f1 a0 [2] df 82 [2] cb 99 [2] c4 83 [2] da 9e [2] d8 9f [2] c3 99 [2] df 9e [2] c3 b1 }

  condition:
    any of them
}