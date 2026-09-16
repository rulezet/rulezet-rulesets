rule TTP_XOR_QUAD_CurrentVersionRun_52f3 {
  strings:
    $key_52f3 = { 01 9c [2] 25 92 [2] 0e be [2] 20 9c [2] 34 87 [2] 3b 9d [2] 25 80 [2] 27 81 [2] 3c 87 [2] 20 80 [2] 3c af }

  condition:
    any of them
}