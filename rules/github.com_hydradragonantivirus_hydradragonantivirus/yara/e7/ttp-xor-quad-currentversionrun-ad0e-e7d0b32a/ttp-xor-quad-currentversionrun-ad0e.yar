rule TTP_XOR_QUAD_CurrentVersionRun_ad0e {
  strings:
    $key_ad0e = { fe 61 [2] da 6f [2] f1 43 [2] df 61 [2] cb 7a [2] c4 60 [2] da 7d [2] d8 7c [2] c3 7a [2] df 7d [2] c3 52 }

  condition:
    any of them
}