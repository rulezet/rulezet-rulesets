rule TTP_XOR_QUAD_CurrentVersionRun_3456 {
  strings:
    $key_3456 = { 67 39 [2] 43 37 [2] 68 1b [2] 46 39 [2] 52 22 [2] 5d 38 [2] 43 25 [2] 41 24 [2] 5a 22 [2] 46 25 [2] 5a 0a }

  condition:
    any of them
}