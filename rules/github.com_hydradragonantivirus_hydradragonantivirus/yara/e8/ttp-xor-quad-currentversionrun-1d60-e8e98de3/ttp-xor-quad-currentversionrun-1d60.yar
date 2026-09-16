rule TTP_XOR_QUAD_CurrentVersionRun_1d60 {
  strings:
    $key_1d60 = { 4e 0f [2] 6a 01 [2] 41 2d [2] 6f 0f [2] 7b 14 [2] 74 0e [2] 6a 13 [2] 68 12 [2] 73 14 [2] 6f 13 [2] 73 3c }

  condition:
    any of them
}