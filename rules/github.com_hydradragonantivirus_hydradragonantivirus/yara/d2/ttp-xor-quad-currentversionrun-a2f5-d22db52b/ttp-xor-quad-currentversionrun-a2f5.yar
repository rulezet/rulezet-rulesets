rule TTP_XOR_QUAD_CurrentVersionRun_a2f5 {
  strings:
    $key_a2f5 = { f1 9a [2] d5 94 [2] fe b8 [2] d0 9a [2] c4 81 [2] cb 9b [2] d5 86 [2] d7 87 [2] cc 81 [2] d0 86 [2] cc a9 }

  condition:
    any of them
}