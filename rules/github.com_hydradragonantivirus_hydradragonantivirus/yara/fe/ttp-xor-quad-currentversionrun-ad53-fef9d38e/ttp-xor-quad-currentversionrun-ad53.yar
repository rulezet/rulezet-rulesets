rule TTP_XOR_QUAD_CurrentVersionRun_ad53 {
  strings:
    $key_ad53 = { fe 3c [2] da 32 [2] f1 1e [2] df 3c [2] cb 27 [2] c4 3d [2] da 20 [2] d8 21 [2] c3 27 [2] df 20 [2] c3 0f }

  condition:
    any of them
}