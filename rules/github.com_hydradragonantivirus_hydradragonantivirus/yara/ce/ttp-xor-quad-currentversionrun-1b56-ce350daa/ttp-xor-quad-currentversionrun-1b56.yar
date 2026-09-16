rule TTP_XOR_QUAD_CurrentVersionRun_1b56 {
  strings:
    $key_1b56 = { 48 39 [2] 6c 37 [2] 47 1b [2] 69 39 [2] 7d 22 [2] 72 38 [2] 6c 25 [2] 6e 24 [2] 75 22 [2] 69 25 [2] 75 0a }

  condition:
    any of them
}