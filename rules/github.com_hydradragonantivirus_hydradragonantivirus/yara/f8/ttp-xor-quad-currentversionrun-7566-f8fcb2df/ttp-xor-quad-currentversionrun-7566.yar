rule TTP_XOR_QUAD_CurrentVersionRun_7566 {
  strings:
    $key_7566 = { 26 09 [2] 02 07 [2] 29 2b [2] 07 09 [2] 13 12 [2] 1c 08 [2] 02 15 [2] 00 14 [2] 1b 12 [2] 07 15 [2] 1b 3a }

  condition:
    any of them
}