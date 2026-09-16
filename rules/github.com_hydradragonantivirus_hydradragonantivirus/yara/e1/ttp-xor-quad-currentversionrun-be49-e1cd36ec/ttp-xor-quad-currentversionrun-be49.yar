rule TTP_XOR_QUAD_CurrentVersionRun_be49 {
  strings:
    $key_be49 = { ed 26 [2] c9 28 [2] e2 04 [2] cc 26 [2] d8 3d [2] d7 27 [2] c9 3a [2] cb 3b [2] d0 3d [2] cc 3a [2] d0 15 }

  condition:
    any of them
}