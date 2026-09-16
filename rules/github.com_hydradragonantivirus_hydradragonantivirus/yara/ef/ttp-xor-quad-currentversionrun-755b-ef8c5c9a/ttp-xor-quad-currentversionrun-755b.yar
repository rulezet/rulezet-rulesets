rule TTP_XOR_QUAD_CurrentVersionRun_755b {
  strings:
    $key_755b = { 26 34 [2] 02 3a [2] 29 16 [2] 07 34 [2] 13 2f [2] 1c 35 [2] 02 28 [2] 00 29 [2] 1b 2f [2] 07 28 [2] 1b 07 }

  condition:
    any of them
}