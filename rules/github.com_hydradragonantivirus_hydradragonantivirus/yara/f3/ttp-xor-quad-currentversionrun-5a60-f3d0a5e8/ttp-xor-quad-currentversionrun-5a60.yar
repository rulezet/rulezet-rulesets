rule TTP_XOR_QUAD_CurrentVersionRun_5a60 {
  strings:
    $key_5a60 = { 09 0f [2] 2d 01 [2] 06 2d [2] 28 0f [2] 3c 14 [2] 33 0e [2] 2d 13 [2] 2f 12 [2] 34 14 [2] 28 13 [2] 34 3c }

  condition:
    any of them
}