rule TTP_XOR_QUAD_CurrentVersionRun_2e73 {
  strings:
    $key_2e73 = { 7d 1c [2] 59 12 [2] 72 3e [2] 5c 1c [2] 48 07 [2] 47 1d [2] 59 00 [2] 5b 01 [2] 40 07 [2] 5c 00 [2] 40 2f }

  condition:
    any of them
}