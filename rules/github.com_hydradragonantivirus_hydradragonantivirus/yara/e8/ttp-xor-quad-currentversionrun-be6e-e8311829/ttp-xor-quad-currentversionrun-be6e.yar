rule TTP_XOR_QUAD_CurrentVersionRun_be6e {
  strings:
    $key_be6e = { ed 01 [2] c9 0f [2] e2 23 [2] cc 01 [2] d8 1a [2] d7 00 [2] c9 1d [2] cb 1c [2] d0 1a [2] cc 1d [2] d0 32 }

  condition:
    any of them
}