rule TTP_XOR_QUAD_CurrentVersionRun_7216 {
  strings:
    $key_7216 = { 21 79 [2] 05 77 [2] 2e 5b [2] 00 79 [2] 14 62 [2] 1b 78 [2] 05 65 [2] 07 64 [2] 1c 62 [2] 00 65 [2] 1c 4a }

  condition:
    any of them
}