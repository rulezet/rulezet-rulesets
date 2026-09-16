rule TTP_XOR_QUAD_CurrentVersionRun_ad1e {
  strings:
    $key_ad1e = { fe 71 [2] da 7f [2] f1 53 [2] df 71 [2] cb 6a [2] c4 70 [2] da 6d [2] d8 6c [2] c3 6a [2] df 6d [2] c3 42 }

  condition:
    any of them
}