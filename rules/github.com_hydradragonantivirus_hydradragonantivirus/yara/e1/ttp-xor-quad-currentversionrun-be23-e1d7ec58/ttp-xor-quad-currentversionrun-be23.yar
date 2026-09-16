rule TTP_XOR_QUAD_CurrentVersionRun_be23 {
  strings:
    $key_be23 = { ed 4c [2] c9 42 [2] e2 6e [2] cc 4c [2] d8 57 [2] d7 4d [2] c9 50 [2] cb 51 [2] d0 57 [2] cc 50 [2] d0 7f }

  condition:
    any of them
}