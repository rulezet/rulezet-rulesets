rule TTP_XOR_QUAD_CurrentVersionRun_75f3 {
  strings:
    $key_75f3 = { 26 9c [2] 02 92 [2] 29 be [2] 07 9c [2] 13 87 [2] 1c 9d [2] 02 80 [2] 00 81 [2] 1b 87 [2] 07 80 [2] 1b af }

  condition:
    any of them
}