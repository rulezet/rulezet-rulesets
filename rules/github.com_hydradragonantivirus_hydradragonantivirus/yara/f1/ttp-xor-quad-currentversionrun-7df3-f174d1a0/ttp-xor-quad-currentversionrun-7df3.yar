rule TTP_XOR_QUAD_CurrentVersionRun_7df3 {
  strings:
    $key_7df3 = { 2e 9c [2] 0a 92 [2] 21 be [2] 0f 9c [2] 1b 87 [2] 14 9d [2] 0a 80 [2] 08 81 [2] 13 87 [2] 0f 80 [2] 13 af }

  condition:
    any of them
}