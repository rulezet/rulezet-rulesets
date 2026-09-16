rule TTP_XOR_QUAD_CurrentVersionRun_a24d {
  strings:
    $key_a24d = { f1 22 [2] d5 2c [2] fe 00 [2] d0 22 [2] c4 39 [2] cb 23 [2] d5 3e [2] d7 3f [2] cc 39 [2] d0 3e [2] cc 11 }

  condition:
    any of them
}