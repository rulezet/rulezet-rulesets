rule TTP_XOR_QUAD_CurrentVersionRun_3860 {
  strings:
    $key_3860 = { 6b 0f [2] 4f 01 [2] 64 2d [2] 4a 0f [2] 5e 14 [2] 51 0e [2] 4f 13 [2] 4d 12 [2] 56 14 [2] 4a 13 [2] 56 3c }

  condition:
    any of them
}