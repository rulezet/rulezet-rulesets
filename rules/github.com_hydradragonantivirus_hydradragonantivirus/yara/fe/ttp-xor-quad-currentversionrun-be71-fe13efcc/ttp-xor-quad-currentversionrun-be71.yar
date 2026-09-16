rule TTP_XOR_QUAD_CurrentVersionRun_be71 {
  strings:
    $key_be71 = { ed 1e [2] c9 10 [2] e2 3c [2] cc 1e [2] d8 05 [2] d7 1f [2] c9 02 [2] cb 03 [2] d0 05 [2] cc 02 [2] d0 2d }

  condition:
    any of them
}