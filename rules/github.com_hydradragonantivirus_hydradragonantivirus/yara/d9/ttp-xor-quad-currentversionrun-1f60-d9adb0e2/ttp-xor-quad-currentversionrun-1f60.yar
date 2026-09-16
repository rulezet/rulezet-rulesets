rule TTP_XOR_QUAD_CurrentVersionRun_1f60 {
  strings:
    $key_1f60 = { 4c 0f [2] 68 01 [2] 43 2d [2] 6d 0f [2] 79 14 [2] 76 0e [2] 68 13 [2] 6a 12 [2] 71 14 [2] 6d 13 [2] 71 3c }

  condition:
    any of them
}