rule TTP_XOR_QUAD_CurrentVersionRun_bee4 {
  strings:
    $key_bee4 = { ed 8b [2] c9 85 [2] e2 a9 [2] cc 8b [2] d8 90 [2] d7 8a [2] c9 97 [2] cb 96 [2] d0 90 [2] cc 97 [2] d0 b8 }

  condition:
    any of them
}