rule TTP_XOR_QUAD_CurrentVersionRun_adf2 {
  strings:
    $key_adf2 = { fe 9d [2] da 93 [2] f1 bf [2] df 9d [2] cb 86 [2] c4 9c [2] da 81 [2] d8 80 [2] c3 86 [2] df 81 [2] c3 ae }

  condition:
    any of them
}