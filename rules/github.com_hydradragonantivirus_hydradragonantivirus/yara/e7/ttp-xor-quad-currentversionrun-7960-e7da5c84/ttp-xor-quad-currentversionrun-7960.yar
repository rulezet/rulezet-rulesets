rule TTP_XOR_QUAD_CurrentVersionRun_7960 {
  strings:
    $key_7960 = { 2a 0f [2] 0e 01 [2] 25 2d [2] 0b 0f [2] 1f 14 [2] 10 0e [2] 0e 13 [2] 0c 12 [2] 17 14 [2] 0b 13 [2] 17 3c }

  condition:
    any of them
}