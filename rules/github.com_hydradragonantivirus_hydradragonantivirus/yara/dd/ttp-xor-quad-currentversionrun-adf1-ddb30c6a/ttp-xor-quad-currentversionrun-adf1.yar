rule TTP_XOR_QUAD_CurrentVersionRun_adf1 {
  strings:
    $key_adf1 = { fe 9e [2] da 90 [2] f1 bc [2] df 9e [2] cb 85 [2] c4 9f [2] da 82 [2] d8 83 [2] c3 85 [2] df 82 [2] c3 ad }

  condition:
    any of them
}