rule TTP_XOR_QUAD_CurrentVersionRun_be35 {
  strings:
    $key_be35 = { ed 5a [2] c9 54 [2] e2 78 [2] cc 5a [2] d8 41 [2] d7 5b [2] c9 46 [2] cb 47 [2] d0 41 [2] cc 46 [2] d0 69 }

  condition:
    any of them
}