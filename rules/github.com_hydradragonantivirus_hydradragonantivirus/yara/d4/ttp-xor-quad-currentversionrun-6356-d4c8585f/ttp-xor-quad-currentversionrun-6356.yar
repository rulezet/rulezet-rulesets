rule TTP_XOR_QUAD_CurrentVersionRun_6356 {
  strings:
    $key_6356 = { 30 39 [2] 14 37 [2] 3f 1b [2] 11 39 [2] 05 22 [2] 0a 38 [2] 14 25 [2] 16 24 [2] 0d 22 [2] 11 25 [2] 0d 0a }

  condition:
    any of them
}