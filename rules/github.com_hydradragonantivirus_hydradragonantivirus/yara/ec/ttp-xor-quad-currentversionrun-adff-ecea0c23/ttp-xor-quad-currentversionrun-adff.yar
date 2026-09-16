rule TTP_XOR_QUAD_CurrentVersionRun_adff {
  strings:
    $key_adff = { fe 90 [2] da 9e [2] f1 b2 [2] df 90 [2] cb 8b [2] c4 91 [2] da 8c [2] d8 8d [2] c3 8b [2] df 8c [2] c3 a3 }

  condition:
    any of them
}