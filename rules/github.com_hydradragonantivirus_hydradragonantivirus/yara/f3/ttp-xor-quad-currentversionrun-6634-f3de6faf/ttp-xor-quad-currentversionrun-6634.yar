rule TTP_XOR_QUAD_CurrentVersionRun_6634 {
  strings:
    $key_6634 = { 35 5b [2] 11 55 [2] 3a 79 [2] 14 5b [2] 00 40 [2] 0f 5a [2] 11 47 [2] 13 46 [2] 08 40 [2] 14 47 [2] 08 68 }

  condition:
    any of them
}