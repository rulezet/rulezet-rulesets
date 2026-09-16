rule TTP_XOR_QUAD_CurrentVersionRun_1e60 {
  strings:
    $key_1e60 = { 4d 0f [2] 69 01 [2] 42 2d [2] 6c 0f [2] 78 14 [2] 77 0e [2] 69 13 [2] 6b 12 [2] 70 14 [2] 6c 13 [2] 70 3c }

  condition:
    any of them
}