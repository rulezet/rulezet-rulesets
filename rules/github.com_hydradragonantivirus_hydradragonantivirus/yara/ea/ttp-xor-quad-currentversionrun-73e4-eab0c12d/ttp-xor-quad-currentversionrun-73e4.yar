rule TTP_XOR_QUAD_CurrentVersionRun_73e4 {
  strings:
    $key_73e4 = { 20 8b [2] 04 85 [2] 2f a9 [2] 01 8b [2] 15 90 [2] 1a 8a [2] 04 97 [2] 06 96 [2] 1d 90 [2] 01 97 [2] 1d b8 }

  condition:
    any of them
}