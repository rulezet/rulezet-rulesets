rule TTP_XOR_QUAD_CurrentVersionRun_7c06 {
  strings:
    $key_7c06 = { 2f 69 [2] 0b 67 [2] 20 4b [2] 0e 69 [2] 1a 72 [2] 15 68 [2] 0b 75 [2] 09 74 [2] 12 72 [2] 0e 75 [2] 12 5a }

  condition:
    any of them
}