rule TTP_XOR_QUAD_CurrentVersionRun_7409 {
  strings:
    $key_7409 = { 27 66 [2] 03 68 [2] 28 44 [2] 06 66 [2] 12 7d [2] 1d 67 [2] 03 7a [2] 01 7b [2] 1a 7d [2] 06 7a [2] 1a 55 }

  condition:
    any of them
}