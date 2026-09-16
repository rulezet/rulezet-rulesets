rule TTP_XOR_QUAD_CurrentVersionRun_be1b {
  strings:
    $key_be1b = { ed 74 [2] c9 7a [2] e2 56 [2] cc 74 [2] d8 6f [2] d7 75 [2] c9 68 [2] cb 69 [2] d0 6f [2] cc 68 [2] d0 47 }

  condition:
    any of them
}