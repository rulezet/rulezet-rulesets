rule TTP_XOR_QUAD_CurrentVersionRun_7532 {
  strings:
    $key_7532 = { 26 5d [2] 02 53 [2] 29 7f [2] 07 5d [2] 13 46 [2] 1c 5c [2] 02 41 [2] 00 40 [2] 1b 46 [2] 07 41 [2] 1b 6e }

  condition:
    any of them
}