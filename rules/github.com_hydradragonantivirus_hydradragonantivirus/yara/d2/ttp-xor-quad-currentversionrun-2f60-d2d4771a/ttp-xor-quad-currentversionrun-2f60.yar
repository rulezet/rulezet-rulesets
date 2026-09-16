rule TTP_XOR_QUAD_CurrentVersionRun_2f60 {
  strings:
    $key_2f60 = { 7c 0f [2] 58 01 [2] 73 2d [2] 5d 0f [2] 49 14 [2] 46 0e [2] 58 13 [2] 5a 12 [2] 41 14 [2] 5d 13 [2] 41 3c }

  condition:
    any of them
}