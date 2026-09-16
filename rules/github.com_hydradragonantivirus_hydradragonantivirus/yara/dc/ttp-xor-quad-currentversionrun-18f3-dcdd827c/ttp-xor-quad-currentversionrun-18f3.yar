rule TTP_XOR_QUAD_CurrentVersionRun_18f3 {
  strings:
    $key_18f3 = { 4b 9c [2] 6f 92 [2] 44 be [2] 6a 9c [2] 7e 87 [2] 71 9d [2] 6f 80 [2] 6d 81 [2] 76 87 [2] 6a 80 [2] 76 af }

  condition:
    any of them
}