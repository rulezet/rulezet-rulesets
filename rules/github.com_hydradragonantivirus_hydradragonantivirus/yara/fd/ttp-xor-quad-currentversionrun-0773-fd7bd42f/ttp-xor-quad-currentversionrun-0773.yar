rule TTP_XOR_QUAD_CurrentVersionRun_0773 {
  strings:
    $key_0773 = { 54 1c [2] 70 12 [2] 5b 3e [2] 75 1c [2] 61 07 [2] 6e 1d [2] 70 00 [2] 72 01 [2] 69 07 [2] 75 00 [2] 69 2f }

  condition:
    any of them
}