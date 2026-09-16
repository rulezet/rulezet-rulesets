rule TTP_XOR_QUAD_CurrentVersionRun_7760 {
  strings:
    $key_7760 = { 24 0f [2] 00 01 [2] 2b 2d [2] 05 0f [2] 11 14 [2] 1e 0e [2] 00 13 [2] 02 12 [2] 19 14 [2] 05 13 [2] 19 3c }

  condition:
    any of them
}