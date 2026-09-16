rule TTP_XOR_QUAD_CurrentVersionRun_7906 {
  strings:
    $key_7906 = { 2a 69 [2] 0e 67 [2] 25 4b [2] 0b 69 [2] 1f 72 [2] 10 68 [2] 0e 75 [2] 0c 74 [2] 17 72 [2] 0b 75 [2] 17 5a }

  condition:
    any of them
}