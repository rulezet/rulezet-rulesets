rule TTP_XOR_QUAD_CurrentVersionRun_be4d {
  strings:
    $key_be4d = { ed 22 [2] c9 2c [2] e2 00 [2] cc 22 [2] d8 39 [2] d7 23 [2] c9 3e [2] cb 3f [2] d0 39 [2] cc 3e [2] d0 11 }

  condition:
    any of them
}