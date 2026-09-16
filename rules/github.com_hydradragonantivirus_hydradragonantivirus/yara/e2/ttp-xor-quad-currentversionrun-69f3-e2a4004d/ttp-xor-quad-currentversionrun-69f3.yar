rule TTP_XOR_QUAD_CurrentVersionRun_69f3 {
  strings:
    $key_69f3 = { 3a 9c [2] 1e 92 [2] 35 be [2] 1b 9c [2] 0f 87 [2] 00 9d [2] 1e 80 [2] 1c 81 [2] 07 87 [2] 1b 80 [2] 07 af }

  condition:
    any of them
}