rule TTP_XOR_QUAD_CurrentVersionRun_a515 {
  strings:
    $key_a515 = { f6 7a [2] d2 74 [2] f9 58 [2] d7 7a [2] c3 61 [2] cc 7b [2] d2 66 [2] d0 67 [2] cb 61 [2] d7 66 [2] cb 49 }

  condition:
    any of them
}