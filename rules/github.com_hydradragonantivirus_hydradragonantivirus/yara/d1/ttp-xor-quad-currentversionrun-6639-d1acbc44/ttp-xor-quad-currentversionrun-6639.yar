rule TTP_XOR_QUAD_CurrentVersionRun_6639 {
  strings:
    $key_6639 = { 35 56 [2] 11 58 [2] 3a 74 [2] 14 56 [2] 00 4d [2] 0f 57 [2] 11 4a [2] 13 4b [2] 08 4d [2] 14 4a [2] 08 65 }

  condition:
    any of them
}