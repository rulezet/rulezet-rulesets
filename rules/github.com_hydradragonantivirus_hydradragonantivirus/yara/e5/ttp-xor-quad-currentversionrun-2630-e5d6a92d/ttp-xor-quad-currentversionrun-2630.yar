rule TTP_XOR_QUAD_CurrentVersionRun_2630 {
  strings:
    $key_2630 = { 75 5f [2] 51 51 [2] 7a 7d [2] 54 5f [2] 40 44 [2] 4f 5e [2] 51 43 [2] 53 42 [2] 48 44 [2] 54 43 [2] 48 6c }

  condition:
    any of them
}