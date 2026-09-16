rule TTP_XOR_QUAD_CurrentVersionRun_ad01 {
  strings:
    $key_ad01 = { fe 6e [2] da 60 [2] f1 4c [2] df 6e [2] cb 75 [2] c4 6f [2] da 72 [2] d8 73 [2] c3 75 [2] df 72 [2] c3 5d }

  condition:
    any of them
}