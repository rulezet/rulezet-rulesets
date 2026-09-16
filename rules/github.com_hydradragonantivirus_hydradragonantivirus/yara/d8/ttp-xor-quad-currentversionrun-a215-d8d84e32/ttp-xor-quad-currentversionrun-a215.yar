rule TTP_XOR_QUAD_CurrentVersionRun_a215 {
  strings:
    $key_a215 = { f1 7a [2] d5 74 [2] fe 58 [2] d0 7a [2] c4 61 [2] cb 7b [2] d5 66 [2] d7 67 [2] cc 61 [2] d0 66 [2] cc 49 }

  condition:
    any of them
}