rule TTP_XOR_QUAD_CurrentVersionRun_2af3 {
  strings:
    $key_2af3 = { 79 9c [2] 5d 92 [2] 76 be [2] 58 9c [2] 4c 87 [2] 43 9d [2] 5d 80 [2] 5f 81 [2] 44 87 [2] 58 80 [2] 44 af }

  condition:
    any of them
}