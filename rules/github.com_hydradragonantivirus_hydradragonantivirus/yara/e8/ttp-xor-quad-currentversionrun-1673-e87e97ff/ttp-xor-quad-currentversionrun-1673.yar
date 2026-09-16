rule TTP_XOR_QUAD_CurrentVersionRun_1673 {
  strings:
    $key_1673 = { 45 1c [2] 61 12 [2] 4a 3e [2] 64 1c [2] 70 07 [2] 7f 1d [2] 61 00 [2] 63 01 [2] 78 07 [2] 64 00 [2] 78 2f }

  condition:
    any of them
}