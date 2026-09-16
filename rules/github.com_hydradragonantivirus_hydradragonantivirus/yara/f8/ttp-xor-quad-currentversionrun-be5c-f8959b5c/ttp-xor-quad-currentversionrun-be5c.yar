rule TTP_XOR_QUAD_CurrentVersionRun_be5c {
  strings:
    $key_be5c = { ed 33 [2] c9 3d [2] e2 11 [2] cc 33 [2] d8 28 [2] d7 32 [2] c9 2f [2] cb 2e [2] d0 28 [2] cc 2f [2] d0 00 }

  condition:
    any of them
}