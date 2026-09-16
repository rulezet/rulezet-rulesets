rule TTP_XOR_QUAD_CurrentVersionRun_6623 {
  strings:
    $key_6623 = { 35 4c [2] 11 42 [2] 3a 6e [2] 14 4c [2] 00 57 [2] 0f 4d [2] 11 50 [2] 13 51 [2] 08 57 [2] 14 50 [2] 08 7f }

  condition:
    any of them
}