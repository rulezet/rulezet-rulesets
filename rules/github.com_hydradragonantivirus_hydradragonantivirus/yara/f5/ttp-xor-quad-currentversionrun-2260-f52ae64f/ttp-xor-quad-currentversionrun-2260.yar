rule TTP_XOR_QUAD_CurrentVersionRun_2260 {
  strings:
    $key_2260 = { 71 0f [2] 55 01 [2] 7e 2d [2] 50 0f [2] 44 14 [2] 4b 0e [2] 55 13 [2] 57 12 [2] 4c 14 [2] 50 13 [2] 4c 3c }

  condition:
    any of them
}