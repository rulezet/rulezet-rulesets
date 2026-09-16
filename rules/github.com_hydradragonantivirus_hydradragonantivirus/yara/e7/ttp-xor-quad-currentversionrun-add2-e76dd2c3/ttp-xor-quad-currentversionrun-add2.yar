rule TTP_XOR_QUAD_CurrentVersionRun_add2 {
  strings:
    $key_add2 = { fe bd [2] da b3 [2] f1 9f [2] df bd [2] cb a6 [2] c4 bc [2] da a1 [2] d8 a0 [2] c3 a6 [2] df a1 [2] c3 8e }

  condition:
    any of them
}