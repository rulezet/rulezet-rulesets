rule TTP_XOR_QUAD_CurrentVersionRun_7203 {
  strings:
    $key_7203 = { 21 6c [2] 05 62 [2] 2e 4e [2] 00 6c [2] 14 77 [2] 1b 6d [2] 05 70 [2] 07 71 [2] 1c 77 [2] 00 70 [2] 1c 5f }

  condition:
    any of them
}