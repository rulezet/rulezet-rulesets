rule TTP_XOR_QUAD_CurrentVersionRun_be70 {
  strings:
    $key_be70 = { ed 1f [2] c9 11 [2] e2 3d [2] cc 1f [2] d8 04 [2] d7 1e [2] c9 03 [2] cb 02 [2] d0 04 [2] cc 03 [2] d0 2c }

  condition:
    any of them
}