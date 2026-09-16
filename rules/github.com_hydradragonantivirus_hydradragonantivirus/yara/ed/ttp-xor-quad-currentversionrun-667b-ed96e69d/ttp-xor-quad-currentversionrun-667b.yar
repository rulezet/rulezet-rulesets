rule TTP_XOR_QUAD_CurrentVersionRun_667b {
  strings:
    $key_667b = { 35 14 [2] 11 1a [2] 3a 36 [2] 14 14 [2] 00 0f [2] 0f 15 [2] 11 08 [2] 13 09 [2] 08 0f [2] 14 08 [2] 08 27 }

  condition:
    any of them
}