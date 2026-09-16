rule TTP_XOR_QUAD_CurrentVersionRun_be41 {
  strings:
    $key_be41 = { ed 2e [2] c9 20 [2] e2 0c [2] cc 2e [2] d8 35 [2] d7 2f [2] c9 32 [2] cb 33 [2] d0 35 [2] cc 32 [2] d0 1d }

  condition:
    any of them
}