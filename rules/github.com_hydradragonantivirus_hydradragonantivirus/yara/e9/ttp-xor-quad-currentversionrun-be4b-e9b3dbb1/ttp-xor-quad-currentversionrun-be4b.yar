rule TTP_XOR_QUAD_CurrentVersionRun_be4b {
  strings:
    $key_be4b = { ed 24 [2] c9 2a [2] e2 06 [2] cc 24 [2] d8 3f [2] d7 25 [2] c9 38 [2] cb 39 [2] d0 3f [2] cc 38 [2] d0 17 }

  condition:
    any of them
}