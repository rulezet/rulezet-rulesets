rule TTP_XOR_QUAD_CurrentVersionRun_be02 {
  strings:
    $key_be02 = { ed 6d [2] c9 63 [2] e2 4f [2] cc 6d [2] d8 76 [2] d7 6c [2] c9 71 [2] cb 70 [2] d0 76 [2] cc 71 [2] d0 5e }

  condition:
    any of them
}