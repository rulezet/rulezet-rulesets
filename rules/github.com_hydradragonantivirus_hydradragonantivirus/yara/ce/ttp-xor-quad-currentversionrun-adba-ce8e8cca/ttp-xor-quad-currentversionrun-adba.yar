rule TTP_XOR_QUAD_CurrentVersionRun_adba {
  strings:
    $key_adba = { fe d5 [2] da db [2] f1 f7 [2] df d5 [2] cb ce [2] c4 d4 [2] da c9 [2] d8 c8 [2] c3 ce [2] df c9 [2] c3 e6 }

  condition:
    any of them
}