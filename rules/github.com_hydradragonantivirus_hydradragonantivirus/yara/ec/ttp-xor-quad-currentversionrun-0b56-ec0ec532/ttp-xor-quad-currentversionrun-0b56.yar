rule TTP_XOR_QUAD_CurrentVersionRun_0b56 {
  strings:
    $key_0b56 = { 58 39 [2] 7c 37 [2] 57 1b [2] 79 39 [2] 6d 22 [2] 62 38 [2] 7c 25 [2] 7e 24 [2] 65 22 [2] 79 25 [2] 65 0a }

  condition:
    any of them
}