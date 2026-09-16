rule TTP_XOR_QUAD_CurrentVersionRun_be45 {
  strings:
    $key_be45 = { ed 2a [2] c9 24 [2] e2 08 [2] cc 2a [2] d8 31 [2] d7 2b [2] c9 36 [2] cb 37 [2] d0 31 [2] cc 36 [2] d0 19 }

  condition:
    any of them
}