rule TTP_XOR_QUAD_CurrentVersionRun_6860 {
  strings:
    $key_6860 = { 3b 0f [2] 1f 01 [2] 34 2d [2] 1a 0f [2] 0e 14 [2] 01 0e [2] 1f 13 [2] 1d 12 [2] 06 14 [2] 1a 13 [2] 06 3c }

  condition:
    any of them
}