rule TTP_XOR_QUAD_CurrentVersionRun_7506 {
  strings:
    $key_7506 = { 26 69 [2] 02 67 [2] 29 4b [2] 07 69 [2] 13 72 [2] 1c 68 [2] 02 75 [2] 00 74 [2] 1b 72 [2] 07 75 [2] 1b 5a }

  condition:
    any of them
}