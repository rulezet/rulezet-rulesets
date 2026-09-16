rule TTP_XOR_QUAD_CurrentVersionRun_7c56 {
  strings:
    $key_7c56 = { 2f 39 [2] 0b 37 [2] 20 1b [2] 0e 39 [2] 1a 22 [2] 15 38 [2] 0b 25 [2] 09 24 [2] 12 22 [2] 0e 25 [2] 12 0a }

  condition:
    any of them
}