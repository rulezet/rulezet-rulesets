rule TTP_XOR_QUAD_CurrentVersionRun_2b56 {
  strings:
    $key_2b56 = { 78 39 [2] 5c 37 [2] 77 1b [2] 59 39 [2] 4d 22 [2] 42 38 [2] 5c 25 [2] 5e 24 [2] 45 22 [2] 59 25 [2] 45 0a }

  condition:
    any of them
}