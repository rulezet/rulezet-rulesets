rule TTP_XOR_QUAD_CurrentVersionRun_a2c7 {
  strings:
    $key_a2c7 = { f1 a8 [2] d5 a6 [2] fe 8a [2] d0 a8 [2] c4 b3 [2] cb a9 [2] d5 b4 [2] d7 b5 [2] cc b3 [2] d0 b4 [2] cc 9b }

  condition:
    any of them
}