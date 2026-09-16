rule TTP_XOR_QUAD_CurrentVersionRun_66f4 {
  strings:
    $key_66f4 = { 35 9b [2] 11 95 [2] 3a b9 [2] 14 9b [2] 00 80 [2] 0f 9a [2] 11 87 [2] 13 86 [2] 08 80 [2] 14 87 [2] 08 a8 }

  condition:
    any of them
}