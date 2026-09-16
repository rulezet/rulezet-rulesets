rule TTP_XOR_QUAD_CurrentVersionRun_6646 {
  strings:
    $key_6646 = { 35 29 [2] 11 27 [2] 3a 0b [2] 14 29 [2] 00 32 [2] 0f 28 [2] 11 35 [2] 13 34 [2] 08 32 [2] 14 35 [2] 08 1a }

  condition:
    any of them
}