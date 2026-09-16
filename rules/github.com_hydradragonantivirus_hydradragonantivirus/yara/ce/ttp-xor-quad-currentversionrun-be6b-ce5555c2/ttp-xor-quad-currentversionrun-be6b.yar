rule TTP_XOR_QUAD_CurrentVersionRun_be6b {
  strings:
    $key_be6b = { ed 04 [2] c9 0a [2] e2 26 [2] cc 04 [2] d8 1f [2] d7 05 [2] c9 18 [2] cb 19 [2] d0 1f [2] cc 18 [2] d0 37 }

  condition:
    any of them
}