rule TTP_XOR_QUAD_CurrentVersionRun_bec6 {
  strings:
    $key_bec6 = { ed a9 [2] c9 a7 [2] e2 8b [2] cc a9 [2] d8 b2 [2] d7 a8 [2] c9 b5 [2] cb b4 [2] d0 b2 [2] cc b5 [2] d0 9a }

  condition:
    any of them
}