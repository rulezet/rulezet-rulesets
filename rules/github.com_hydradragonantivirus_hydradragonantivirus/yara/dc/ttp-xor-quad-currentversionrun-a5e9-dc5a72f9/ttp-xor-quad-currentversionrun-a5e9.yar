rule TTP_XOR_QUAD_CurrentVersionRun_a5e9 {
  strings:
    $key_a5e9 = { f6 86 [2] d2 88 [2] f9 a4 [2] d7 86 [2] c3 9d [2] cc 87 [2] d2 9a [2] d0 9b [2] cb 9d [2] d7 9a [2] cb b5 }

  condition:
    any of them
}