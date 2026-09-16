rule TTP_XOR_QUAD_CurrentVersionRun_5260 {
  strings:
    $key_5260 = { 01 0f [2] 25 01 [2] 0e 2d [2] 20 0f [2] 34 14 [2] 3b 0e [2] 25 13 [2] 27 12 [2] 3c 14 [2] 20 13 [2] 3c 3c }

  condition:
    any of them
}