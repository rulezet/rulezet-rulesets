rule TTP_XOR_QUAD_CurrentVersionRun_b9d7 {
  strings:
    $key_b9d7 = { ea b8 [2] ce b6 [2] e5 9a [2] cb b8 [2] df a3 [2] d0 b9 [2] ce a4 [2] cc a5 [2] d7 a3 [2] cb a4 [2] d7 8b }

  condition:
    any of them
}