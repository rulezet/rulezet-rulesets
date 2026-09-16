rule TTP_XOR_QUAD_CurrentVersionRun_7223 {
  strings:
    $key_7223 = { 21 4c [2] 05 42 [2] 2e 6e [2] 00 4c [2] 14 57 [2] 1b 4d [2] 05 50 [2] 07 51 [2] 1c 57 [2] 00 50 [2] 1c 7f }

  condition:
    any of them
}