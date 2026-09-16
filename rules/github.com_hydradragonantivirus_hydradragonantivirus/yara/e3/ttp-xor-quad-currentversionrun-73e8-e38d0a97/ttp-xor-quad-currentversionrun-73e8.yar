rule TTP_XOR_QUAD_CurrentVersionRun_73e8 {
  strings:
    $key_73e8 = { 20 87 [2] 04 89 [2] 2f a5 [2] 01 87 [2] 15 9c [2] 1a 86 [2] 04 9b [2] 06 9a [2] 1d 9c [2] 01 9b [2] 1d b4 }

  condition:
    any of them
}