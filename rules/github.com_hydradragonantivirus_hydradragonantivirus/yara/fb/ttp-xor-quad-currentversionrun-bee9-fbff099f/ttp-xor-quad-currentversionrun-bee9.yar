rule TTP_XOR_QUAD_CurrentVersionRun_bee9 {
  strings:
    $key_bee9 = { ed 86 [2] c9 88 [2] e2 a4 [2] cc 86 [2] d8 9d [2] d7 87 [2] c9 9a [2] cb 9b [2] d0 9d [2] cc 9a [2] d0 b5 }

  condition:
    any of them
}