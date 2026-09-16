rule TTP_XOR_QUAD_CurrentVersionRun_7b1b {
  strings:
    $key_7b1b = { 28 74 [2] 0c 7a [2] 27 56 [2] 09 74 [2] 1d 6f [2] 12 75 [2] 0c 68 [2] 0e 69 [2] 15 6f [2] 09 68 [2] 15 47 }

  condition:
    any of them
}