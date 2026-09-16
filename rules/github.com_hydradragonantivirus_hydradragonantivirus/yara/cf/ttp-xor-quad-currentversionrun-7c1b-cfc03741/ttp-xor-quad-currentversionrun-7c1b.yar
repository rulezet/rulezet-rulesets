rule TTP_XOR_QUAD_CurrentVersionRun_7c1b {
  strings:
    $key_7c1b = { 2f 74 [2] 0b 7a [2] 20 56 [2] 0e 74 [2] 1a 6f [2] 15 75 [2] 0b 68 [2] 09 69 [2] 12 6f [2] 0e 68 [2] 12 47 }

  condition:
    any of them
}