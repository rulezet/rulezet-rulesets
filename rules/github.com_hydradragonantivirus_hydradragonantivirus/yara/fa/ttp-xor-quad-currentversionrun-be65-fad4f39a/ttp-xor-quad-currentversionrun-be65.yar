rule TTP_XOR_QUAD_CurrentVersionRun_be65 {
  strings:
    $key_be65 = { ed 0a [2] c9 04 [2] e2 28 [2] cc 0a [2] d8 11 [2] d7 0b [2] c9 16 [2] cb 17 [2] d0 11 [2] cc 16 [2] d0 39 }

  condition:
    any of them
}