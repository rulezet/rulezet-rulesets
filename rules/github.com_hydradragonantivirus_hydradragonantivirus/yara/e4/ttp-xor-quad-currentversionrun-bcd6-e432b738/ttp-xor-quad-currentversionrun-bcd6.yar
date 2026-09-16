rule TTP_XOR_QUAD_CurrentVersionRun_bcd6 {
  strings:
    $key_bcd6 = { ef b9 [2] cb b7 [2] e0 9b [2] ce b9 [2] da a2 [2] d5 b8 [2] cb a5 [2] c9 a4 [2] d2 a2 [2] ce a5 [2] d2 8a }

  condition:
    any of them
}