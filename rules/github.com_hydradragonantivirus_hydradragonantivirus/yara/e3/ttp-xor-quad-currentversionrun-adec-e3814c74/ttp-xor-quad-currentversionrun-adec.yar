rule TTP_XOR_QUAD_CurrentVersionRun_adec {
  strings:
    $key_adec = { fe 83 [2] da 8d [2] f1 a1 [2] df 83 [2] cb 98 [2] c4 82 [2] da 9f [2] d8 9e [2] c3 98 [2] df 9f [2] c3 b0 }

  condition:
    any of them
}