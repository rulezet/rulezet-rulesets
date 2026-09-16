rule TTP_XOR_QUAD_CurrentVersionRun_f472 {
  strings:
    $key_f472 = { a7 1d [2] 83 13 [2] a8 3f [2] 86 1d [2] 92 06 [2] 9d 1c [2] 83 01 [2] 81 00 [2] 9a 06 [2] 86 01 [2] 9a 2e }

  condition:
    any of them
}