rule TTP_XOR_QUAD_CurrentVersionRun_6460 {
  strings:
    $key_6460 = { 37 0f [2] 13 01 [2] 38 2d [2] 16 0f [2] 02 14 [2] 0d 0e [2] 13 13 [2] 11 12 [2] 0a 14 [2] 16 13 [2] 0a 3c }

  condition:
    any of them
}