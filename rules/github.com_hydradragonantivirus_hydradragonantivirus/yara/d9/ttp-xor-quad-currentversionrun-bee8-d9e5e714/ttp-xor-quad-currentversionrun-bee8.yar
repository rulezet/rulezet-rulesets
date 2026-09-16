rule TTP_XOR_QUAD_CurrentVersionRun_bee8 {
  strings:
    $key_bee8 = { ed 87 [2] c9 89 [2] e2 a5 [2] cc 87 [2] d8 9c [2] d7 86 [2] c9 9b [2] cb 9a [2] d0 9c [2] cc 9b [2] d0 b4 }

  condition:
    any of them
}