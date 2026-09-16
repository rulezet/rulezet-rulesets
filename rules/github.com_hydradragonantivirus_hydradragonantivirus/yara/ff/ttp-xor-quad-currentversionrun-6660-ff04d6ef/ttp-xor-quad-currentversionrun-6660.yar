rule TTP_XOR_QUAD_CurrentVersionRun_6660 {
  strings:
    $key_6660 = { 35 0f [2] 11 01 [2] 3a 2d [2] 14 0f [2] 00 14 [2] 0f 0e [2] 11 13 [2] 13 12 [2] 08 14 [2] 14 13 [2] 08 3c }

  condition:
    any of them
}