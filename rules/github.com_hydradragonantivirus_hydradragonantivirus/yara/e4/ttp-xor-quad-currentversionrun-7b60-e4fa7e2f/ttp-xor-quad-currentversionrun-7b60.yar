rule TTP_XOR_QUAD_CurrentVersionRun_7b60 {
  strings:
    $key_7b60 = { 28 0f [2] 0c 01 [2] 27 2d [2] 09 0f [2] 1d 14 [2] 12 0e [2] 0c 13 [2] 0e 12 [2] 15 14 [2] 09 13 [2] 15 3c }

  condition:
    any of them
}