rule TTP_XOR_QUAD_CurrentVersionRun_be3b {
  strings:
    $key_be3b = { ed 54 [2] c9 5a [2] e2 76 [2] cc 54 [2] d8 4f [2] d7 55 [2] c9 48 [2] cb 49 [2] d0 4f [2] cc 48 [2] d0 67 }

  condition:
    any of them
}