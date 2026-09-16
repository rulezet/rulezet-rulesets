rule TTP_XOR_QUAD_CurrentVersionRun_47f3 {
  strings:
    $key_47f3 = { 14 9c [2] 30 92 [2] 1b be [2] 35 9c [2] 21 87 [2] 2e 9d [2] 30 80 [2] 32 81 [2] 29 87 [2] 35 80 [2] 29 af }

  condition:
    any of them
}