rule TTP_XOR_QUAD_CurrentVersionRun_6340 {
  strings:
    $key_6340 = { 30 2f [2] 14 21 [2] 3f 0d [2] 11 2f [2] 05 34 [2] 0a 2e [2] 14 33 [2] 16 32 [2] 0d 34 [2] 11 33 [2] 0d 1c }

  condition:
    any of them
}