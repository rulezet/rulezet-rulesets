rule TTP_XOR_QUAD_CurrentVersionRun_65f3 {
  strings:
    $key_65f3 = { 36 9c [2] 12 92 [2] 39 be [2] 17 9c [2] 03 87 [2] 0c 9d [2] 12 80 [2] 10 81 [2] 0b 87 [2] 17 80 [2] 0b af }

  condition:
    any of them
}