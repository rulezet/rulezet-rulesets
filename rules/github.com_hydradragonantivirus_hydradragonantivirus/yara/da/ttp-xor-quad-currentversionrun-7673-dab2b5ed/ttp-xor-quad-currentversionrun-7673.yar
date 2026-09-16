rule TTP_XOR_QUAD_CurrentVersionRun_7673 {
  strings:
    $key_7673 = { 25 1c [2] 01 12 [2] 2a 3e [2] 04 1c [2] 10 07 [2] 1f 1d [2] 01 00 [2] 03 01 [2] 18 07 [2] 04 00 [2] 18 2f }

  condition:
    any of them
}