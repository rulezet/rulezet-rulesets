rule TTP_XOR_QUAD_CurrentVersionRun_be0e {
  strings:
    $key_be0e = { ed 61 [2] c9 6f [2] e2 43 [2] cc 61 [2] d8 7a [2] d7 60 [2] c9 7d [2] cb 7c [2] d0 7a [2] cc 7d [2] d0 52 }

  condition:
    any of them
}