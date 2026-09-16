rule TTP_XOR_QUAD_CurrentVersionRun_a2c1 {
  strings:
    $key_a2c1 = { f1 ae [2] d5 a0 [2] fe 8c [2] d0 ae [2] c4 b5 [2] cb af [2] d5 b2 [2] d7 b3 [2] cc b5 [2] d0 b2 [2] cc 9d }

  condition:
    any of them
}