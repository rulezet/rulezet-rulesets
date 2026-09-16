rule TTP_XOR_QUAD_CurrentVersionRun_be76 {
  strings:
    $key_be76 = { ed 19 [2] c9 17 [2] e2 3b [2] cc 19 [2] d8 02 [2] d7 18 [2] c9 05 [2] cb 04 [2] d0 02 [2] cc 05 [2] d0 2a }

  condition:
    any of them
}