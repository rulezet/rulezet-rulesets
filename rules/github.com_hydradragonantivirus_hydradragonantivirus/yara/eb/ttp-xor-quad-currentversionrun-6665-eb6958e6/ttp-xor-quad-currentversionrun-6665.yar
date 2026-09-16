rule TTP_XOR_QUAD_CurrentVersionRun_6665 {
  strings:
    $key_6665 = { 35 0a [2] 11 04 [2] 3a 28 [2] 14 0a [2] 00 11 [2] 0f 0b [2] 11 16 [2] 13 17 [2] 08 11 [2] 14 16 [2] 08 39 }

  condition:
    any of them
}