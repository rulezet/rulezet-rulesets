rule TTP_XOR_QUAD_CurrentVersionRun_4b56 {
  strings:
    $key_4b56 = { 18 39 [2] 3c 37 [2] 17 1b [2] 39 39 [2] 2d 22 [2] 22 38 [2] 3c 25 [2] 3e 24 [2] 25 22 [2] 39 25 [2] 25 0a }

  condition:
    any of them
}