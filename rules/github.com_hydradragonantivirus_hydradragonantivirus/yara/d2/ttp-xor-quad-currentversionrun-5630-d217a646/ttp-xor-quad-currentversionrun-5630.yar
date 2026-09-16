rule TTP_XOR_QUAD_CurrentVersionRun_5630 {
  strings:
    $key_5630 = { 05 5f [2] 21 51 [2] 0a 7d [2] 24 5f [2] 30 44 [2] 3f 5e [2] 21 43 [2] 23 42 [2] 38 44 [2] 24 43 [2] 38 6c }

  condition:
    any of them
}