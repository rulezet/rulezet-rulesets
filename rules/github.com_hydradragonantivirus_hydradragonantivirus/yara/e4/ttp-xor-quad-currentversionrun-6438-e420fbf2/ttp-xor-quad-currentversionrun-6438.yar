rule TTP_XOR_QUAD_CurrentVersionRun_6438 {
  strings:
    $key_6438 = { 37 57 [2] 13 59 [2] 38 75 [2] 16 57 [2] 02 4c [2] 0d 56 [2] 13 4b [2] 11 4a [2] 0a 4c [2] 16 4b [2] 0a 64 }

  condition:
    any of them
}