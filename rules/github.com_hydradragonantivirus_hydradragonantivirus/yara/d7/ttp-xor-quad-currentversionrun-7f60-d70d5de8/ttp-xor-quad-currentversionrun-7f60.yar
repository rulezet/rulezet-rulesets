rule TTP_XOR_QUAD_CurrentVersionRun_7f60 {
  strings:
    $key_7f60 = { 2c 0f [2] 08 01 [2] 23 2d [2] 0d 0f [2] 19 14 [2] 16 0e [2] 08 13 [2] 0a 12 [2] 11 14 [2] 0d 13 [2] 11 3c }

  condition:
    any of them
}