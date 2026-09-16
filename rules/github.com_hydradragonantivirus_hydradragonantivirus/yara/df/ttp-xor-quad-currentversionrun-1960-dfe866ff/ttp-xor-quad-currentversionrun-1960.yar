rule TTP_XOR_QUAD_CurrentVersionRun_1960 {
  strings:
    $key_1960 = { 4a 0f [2] 6e 01 [2] 45 2d [2] 6b 0f [2] 7f 14 [2] 70 0e [2] 6e 13 [2] 6c 12 [2] 77 14 [2] 6b 13 [2] 77 3c }

  condition:
    any of them
}