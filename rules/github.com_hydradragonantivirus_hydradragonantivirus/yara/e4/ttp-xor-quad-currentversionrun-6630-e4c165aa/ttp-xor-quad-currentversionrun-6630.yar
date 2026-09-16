rule TTP_XOR_QUAD_CurrentVersionRun_6630 {
  strings:
    $key_6630 = { 35 5f [2] 11 51 [2] 3a 7d [2] 14 5f [2] 00 44 [2] 0f 5e [2] 11 43 [2] 13 42 [2] 08 44 [2] 14 43 [2] 08 6c }

  condition:
    any of them
}