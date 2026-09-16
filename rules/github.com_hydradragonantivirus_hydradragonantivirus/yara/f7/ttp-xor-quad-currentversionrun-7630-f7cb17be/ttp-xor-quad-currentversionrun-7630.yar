rule TTP_XOR_QUAD_CurrentVersionRun_7630 {
  strings:
    $key_7630 = { 25 5f [2] 01 51 [2] 2a 7d [2] 04 5f [2] 10 44 [2] 1f 5e [2] 01 43 [2] 03 42 [2] 18 44 [2] 04 43 [2] 18 6c }

  condition:
    any of them
}