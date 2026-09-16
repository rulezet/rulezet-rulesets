rule TTP_XOR_QUAD_CurrentVersionRun_7438 {
  strings:
    $key_7438 = { 27 57 [2] 03 59 [2] 28 75 [2] 06 57 [2] 12 4c [2] 1d 56 [2] 03 4b [2] 01 4a [2] 1a 4c [2] 06 4b [2] 1a 64 }

  condition:
    any of them
}