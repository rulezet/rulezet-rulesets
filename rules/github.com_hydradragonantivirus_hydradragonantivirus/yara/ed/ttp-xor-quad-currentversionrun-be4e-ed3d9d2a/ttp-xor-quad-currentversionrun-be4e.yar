rule TTP_XOR_QUAD_CurrentVersionRun_be4e {
  strings:
    $key_be4e = { ed 21 [2] c9 2f [2] e2 03 [2] cc 21 [2] d8 3a [2] d7 20 [2] c9 3d [2] cb 3c [2] d0 3a [2] cc 3d [2] d0 12 }

  condition:
    any of them
}