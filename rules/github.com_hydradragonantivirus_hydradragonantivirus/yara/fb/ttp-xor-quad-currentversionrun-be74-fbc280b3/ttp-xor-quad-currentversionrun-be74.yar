rule TTP_XOR_QUAD_CurrentVersionRun_be74 {
  strings:
    $key_be74 = { ed 1b [2] c9 15 [2] e2 39 [2] cc 1b [2] d8 00 [2] d7 1a [2] c9 07 [2] cb 06 [2] d0 00 [2] cc 07 [2] d0 28 }

  condition:
    any of them
}