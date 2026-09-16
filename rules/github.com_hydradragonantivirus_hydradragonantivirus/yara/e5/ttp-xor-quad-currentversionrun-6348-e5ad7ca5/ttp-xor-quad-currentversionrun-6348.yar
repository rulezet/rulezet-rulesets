rule TTP_XOR_QUAD_CurrentVersionRun_6348 {
  strings:
    $key_6348 = { 30 27 [2] 14 29 [2] 3f 05 [2] 11 27 [2] 05 3c [2] 0a 26 [2] 14 3b [2] 16 3a [2] 0d 3c [2] 11 3b [2] 0d 14 }

  condition:
    any of them
}