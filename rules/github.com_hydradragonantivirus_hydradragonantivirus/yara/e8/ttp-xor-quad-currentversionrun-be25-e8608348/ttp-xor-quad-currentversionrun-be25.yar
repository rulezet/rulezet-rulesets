rule TTP_XOR_QUAD_CurrentVersionRun_be25 {
  strings:
    $key_be25 = { ed 4a [2] c9 44 [2] e2 68 [2] cc 4a [2] d8 51 [2] d7 4b [2] c9 56 [2] cb 57 [2] d0 51 [2] cc 56 [2] d0 79 }

  condition:
    any of them
}