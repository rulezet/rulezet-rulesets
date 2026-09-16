rule TTP_XOR_QUAD_CurrentVersionRun_a5c7 {
  strings:
    $key_a5c7 = { f6 a8 [2] d2 a6 [2] f9 8a [2] d7 a8 [2] c3 b3 [2] cc a9 [2] d2 b4 [2] d0 b5 [2] cb b3 [2] d7 b4 [2] cb 9b }

  condition:
    any of them
}