rule TTP_XOR_QUAD_CurrentVersionRun_0673 {
  strings:
    $key_0673 = { 55 1c [2] 71 12 [2] 5a 3e [2] 74 1c [2] 60 07 [2] 6f 1d [2] 71 00 [2] 73 01 [2] 68 07 [2] 74 00 [2] 68 2f }

  condition:
    any of them
}