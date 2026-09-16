rule TTP_XOR_QUAD_CurrentVersionRun_be48 {
  strings:
    $key_be48 = { ed 27 [2] c9 29 [2] e2 05 [2] cc 27 [2] d8 3c [2] d7 26 [2] c9 3b [2] cb 3a [2] d0 3c [2] cc 3b [2] d0 14 }

  condition:
    any of them
}