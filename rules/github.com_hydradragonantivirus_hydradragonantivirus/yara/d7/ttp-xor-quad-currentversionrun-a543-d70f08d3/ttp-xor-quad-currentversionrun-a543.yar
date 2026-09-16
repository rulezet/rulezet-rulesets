rule TTP_XOR_QUAD_CurrentVersionRun_a543 {
  strings:
    $key_a543 = { f6 2c [2] d2 22 [2] f9 0e [2] d7 2c [2] c3 37 [2] cc 2d [2] d2 30 [2] d0 31 [2] cb 37 [2] d7 30 [2] cb 1f }

  condition:
    any of them
}