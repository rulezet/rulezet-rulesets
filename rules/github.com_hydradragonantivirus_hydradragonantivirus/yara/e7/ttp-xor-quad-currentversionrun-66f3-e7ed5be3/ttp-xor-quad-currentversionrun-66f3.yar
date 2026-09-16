rule TTP_XOR_QUAD_CurrentVersionRun_66f3 {
  strings:
    $key_66f3 = { 35 9c [2] 11 92 [2] 3a be [2] 14 9c [2] 00 87 [2] 0f 9d [2] 11 80 [2] 13 81 [2] 08 87 [2] 14 80 [2] 08 af }

  condition:
    any of them
}