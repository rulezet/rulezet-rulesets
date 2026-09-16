rule TTP_XOR_QUAD_CurrentVersionRun_7428 {
  strings:
    $key_7428 = { 27 47 [2] 03 49 [2] 28 65 [2] 06 47 [2] 12 5c [2] 1d 46 [2] 03 5b [2] 01 5a [2] 1a 5c [2] 06 5b [2] 1a 74 }

  condition:
    any of them
}