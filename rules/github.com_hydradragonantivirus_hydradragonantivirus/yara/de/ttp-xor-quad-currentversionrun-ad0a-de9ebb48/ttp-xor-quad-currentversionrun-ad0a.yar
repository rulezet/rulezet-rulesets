rule TTP_XOR_QUAD_CurrentVersionRun_ad0a {
  strings:
    $key_ad0a = { fe 65 [2] da 6b [2] f1 47 [2] df 65 [2] cb 7e [2] c4 64 [2] da 79 [2] d8 78 [2] c3 7e [2] df 79 [2] c3 56 }

  condition:
    any of them
}