rule TTP_XOR_QUAD_CurrentVersionRun_beeb {
  strings:
    $key_beeb = { ed 84 [2] c9 8a [2] e2 a6 [2] cc 84 [2] d8 9f [2] d7 85 [2] c9 98 [2] cb 99 [2] d0 9f [2] cc 98 [2] d0 b7 }

  condition:
    any of them
}