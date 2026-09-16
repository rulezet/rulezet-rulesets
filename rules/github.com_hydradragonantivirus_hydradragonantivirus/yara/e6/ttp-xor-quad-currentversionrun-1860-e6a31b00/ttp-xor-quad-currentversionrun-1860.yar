rule TTP_XOR_QUAD_CurrentVersionRun_1860 {
  strings:
    $key_1860 = { 4b 0f [2] 6f 01 [2] 44 2d [2] 6a 0f [2] 7e 14 [2] 71 0e [2] 6f 13 [2] 6d 12 [2] 76 14 [2] 6a 13 [2] 76 3c }

  condition:
    any of them
}