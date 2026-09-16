rule TTP_XOR_QUAD_CurrentVersionRun_be51 {
  strings:
    $key_be51 = { ed 3e [2] c9 30 [2] e2 1c [2] cc 3e [2] d8 25 [2] d7 3f [2] c9 22 [2] cb 23 [2] d0 25 [2] cc 22 [2] d0 0d }

  condition:
    any of them
}