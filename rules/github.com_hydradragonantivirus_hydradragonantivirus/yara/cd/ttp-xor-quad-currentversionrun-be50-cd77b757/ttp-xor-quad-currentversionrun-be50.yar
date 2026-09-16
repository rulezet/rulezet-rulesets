rule TTP_XOR_QUAD_CurrentVersionRun_be50 {
  strings:
    $key_be50 = { ed 3f [2] c9 31 [2] e2 1d [2] cc 3f [2] d8 24 [2] d7 3e [2] c9 23 [2] cb 22 [2] d0 24 [2] cc 23 [2] d0 0c }

  condition:
    any of them
}