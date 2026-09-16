rule TTP_XOR_QUAD_CurrentVersionRun_6773 {
  strings:
    $key_6773 = { 34 1c [2] 10 12 [2] 3b 3e [2] 15 1c [2] 01 07 [2] 0e 1d [2] 10 00 [2] 12 01 [2] 09 07 [2] 15 00 [2] 09 2f }

  condition:
    any of them
}