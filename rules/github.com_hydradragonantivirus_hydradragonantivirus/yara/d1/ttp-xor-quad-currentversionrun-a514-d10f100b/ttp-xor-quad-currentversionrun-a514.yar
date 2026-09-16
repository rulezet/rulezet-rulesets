rule TTP_XOR_QUAD_CurrentVersionRun_a514 {
  strings:
    $key_a514 = { f6 7b [2] d2 75 [2] f9 59 [2] d7 7b [2] c3 60 [2] cc 7a [2] d2 67 [2] d0 66 [2] cb 60 [2] d7 67 [2] cb 48 }

  condition:
    any of them
}