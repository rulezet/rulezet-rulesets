rule TTP_XOR_QUAD_CurrentVersionRun_b9c6 {
  strings:
    $key_b9c6 = { ea a9 [2] ce a7 [2] e5 8b [2] cb a9 [2] df b2 [2] d0 a8 [2] ce b5 [2] cc b4 [2] d7 b2 [2] cb b5 [2] d7 9a }

  condition:
    any of them
}