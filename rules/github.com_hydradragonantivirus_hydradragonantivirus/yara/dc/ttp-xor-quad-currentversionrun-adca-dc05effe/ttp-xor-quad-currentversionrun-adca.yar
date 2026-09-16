rule TTP_XOR_QUAD_CurrentVersionRun_adca {
  strings:
    $key_adca = { fe a5 [2] da ab [2] f1 87 [2] df a5 [2] cb be [2] c4 a4 [2] da b9 [2] d8 b8 [2] c3 be [2] df b9 [2] c3 96 }

  condition:
    any of them
}