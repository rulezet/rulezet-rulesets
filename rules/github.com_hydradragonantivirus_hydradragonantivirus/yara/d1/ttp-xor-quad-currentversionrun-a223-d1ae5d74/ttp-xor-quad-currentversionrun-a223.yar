rule TTP_XOR_QUAD_CurrentVersionRun_a223 {
  strings:
    $key_a223 = { f1 4c [2] d5 42 [2] fe 6e [2] d0 4c [2] c4 57 [2] cb 4d [2] d5 50 [2] d7 51 [2] cc 57 [2] d0 50 [2] cc 7f }

  condition:
    any of them
}