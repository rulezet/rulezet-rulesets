rule TTP_XOR_QUAD_CurrentVersionRun_be78 {
  strings:
    $key_be78 = { ed 17 [2] c9 19 [2] e2 35 [2] cc 17 [2] d8 0c [2] d7 16 [2] c9 0b [2] cb 0a [2] d0 0c [2] cc 0b [2] d0 24 }

  condition:
    any of them
}