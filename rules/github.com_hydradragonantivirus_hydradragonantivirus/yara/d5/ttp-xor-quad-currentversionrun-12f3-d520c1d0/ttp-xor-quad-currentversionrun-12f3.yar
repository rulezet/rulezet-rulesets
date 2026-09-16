rule TTP_XOR_QUAD_CurrentVersionRun_12f3 {
  strings:
    $key_12f3 = { 41 9c [2] 65 92 [2] 4e be [2] 60 9c [2] 74 87 [2] 7b 9d [2] 65 80 [2] 67 81 [2] 7c 87 [2] 60 80 [2] 7c af }

  condition:
    any of them
}