rule TTP_XOR_QUAD_CurrentVersionRun_a54d {
  strings:
    $key_a54d = { f6 22 [2] d2 2c [2] f9 00 [2] d7 22 [2] c3 39 [2] cc 23 [2] d2 3e [2] d0 3f [2] cb 39 [2] d7 3e [2] cb 11 }

  condition:
    any of them
}