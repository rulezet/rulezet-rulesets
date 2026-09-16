rule TTP_XOR_QUAD_CurrentVersionRun_adf6 {
  strings:
    $key_adf6 = { fe 99 [2] da 97 [2] f1 bb [2] df 99 [2] cb 82 [2] c4 98 [2] da 85 [2] d8 84 [2] c3 82 [2] df 85 [2] c3 aa }

  condition:
    any of them
}