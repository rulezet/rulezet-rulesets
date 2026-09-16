rule TTP_XOR_QUAD_CurrentVersionRun_6760 {
  strings:
    $key_6760 = { 34 0f [2] 10 01 [2] 3b 2d [2] 15 0f [2] 01 14 [2] 0e 0e [2] 10 13 [2] 12 12 [2] 09 14 [2] 15 13 [2] 09 3c }

  condition:
    any of them
}