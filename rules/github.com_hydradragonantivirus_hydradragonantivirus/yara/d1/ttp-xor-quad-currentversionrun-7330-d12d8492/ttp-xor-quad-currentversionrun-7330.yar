rule TTP_XOR_QUAD_CurrentVersionRun_7330 {
  strings:
    $key_7330 = { 20 5f [2] 04 51 [2] 2f 7d [2] 01 5f [2] 15 44 [2] 1a 5e [2] 04 43 [2] 06 42 [2] 1d 44 [2] 01 43 [2] 1d 6c }

  condition:
    any of them
}