rule TTP_XOR_QUAD_CurrentVersionRun_adfd {
  strings:
    $key_adfd = { fe 92 [2] da 9c [2] f1 b0 [2] df 92 [2] cb 89 [2] c4 93 [2] da 8e [2] d8 8f [2] c3 89 [2] df 8e [2] c3 a1 }

  condition:
    any of them
}