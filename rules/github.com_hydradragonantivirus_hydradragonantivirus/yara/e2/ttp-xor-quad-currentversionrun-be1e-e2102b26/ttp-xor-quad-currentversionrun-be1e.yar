rule TTP_XOR_QUAD_CurrentVersionRun_be1e {
  strings:
    $key_be1e = { ed 71 [2] c9 7f [2] e2 53 [2] cc 71 [2] d8 6a [2] d7 70 [2] c9 6d [2] cb 6c [2] d0 6a [2] cc 6d [2] d0 42 }

  condition:
    any of them
}