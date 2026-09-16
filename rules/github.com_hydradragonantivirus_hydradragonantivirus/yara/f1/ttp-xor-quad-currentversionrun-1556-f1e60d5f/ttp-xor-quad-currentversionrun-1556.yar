rule TTP_XOR_QUAD_CurrentVersionRun_1556 {
  strings:
    $key_1556 = { 46 39 [2] 62 37 [2] 49 1b [2] 67 39 [2] 73 22 [2] 7c 38 [2] 62 25 [2] 60 24 [2] 7b 22 [2] 67 25 [2] 7b 0a }

  condition:
    any of them
}