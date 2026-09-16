rule TTP_XOR_QUAD_CurrentVersionRun_a207 {
  strings:
    $key_a207 = { f1 68 [2] d5 66 [2] fe 4a [2] d0 68 [2] c4 73 [2] cb 69 [2] d5 74 [2] d7 75 [2] cc 73 [2] d0 74 [2] cc 5b }

  condition:
    any of them
}