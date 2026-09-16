rule TTP_XOR_QUAD_CurrentVersionRun_4e60 {
  strings:
    $key_4e60 = { 1d 0f [2] 39 01 [2] 12 2d [2] 3c 0f [2] 28 14 [2] 27 0e [2] 39 13 [2] 3b 12 [2] 20 14 [2] 3c 13 [2] 20 3c }

  condition:
    any of them
}