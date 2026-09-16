rule TTP_XOR_QUAD_CurrentVersionRun_4d06 {
  strings:
    $key_4d06 = { 1e 69 [2] 3a 67 [2] 11 4b [2] 3f 69 [2] 2b 72 [2] 24 68 [2] 3a 75 [2] 38 74 [2] 23 72 [2] 3f 75 [2] 23 5a }

  condition:
    any of them
}