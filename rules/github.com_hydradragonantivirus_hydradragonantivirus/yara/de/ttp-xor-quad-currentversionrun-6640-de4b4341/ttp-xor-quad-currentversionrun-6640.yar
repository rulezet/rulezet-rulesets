rule TTP_XOR_QUAD_CurrentVersionRun_6640 {
  strings:
    $key_6640 = { 35 2f [2] 11 21 [2] 3a 0d [2] 14 2f [2] 00 34 [2] 0f 2e [2] 11 33 [2] 13 32 [2] 08 34 [2] 14 33 [2] 08 1c }

  condition:
    any of them
}