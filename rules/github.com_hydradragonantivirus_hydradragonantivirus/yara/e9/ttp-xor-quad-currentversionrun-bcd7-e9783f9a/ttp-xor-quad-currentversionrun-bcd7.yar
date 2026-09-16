rule TTP_XOR_QUAD_CurrentVersionRun_bcd7 {
  strings:
    $key_bcd7 = { ef b8 [2] cb b6 [2] e0 9a [2] ce b8 [2] da a3 [2] d5 b9 [2] cb a4 [2] c9 a5 [2] d2 a3 [2] ce a4 [2] d2 8b }

  condition:
    any of them
}