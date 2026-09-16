rule TTP_XOR_QUAD_CurrentVersionRun_7730 {
  strings:
    $key_7730 = { 24 5f [2] 00 51 [2] 2b 7d [2] 05 5f [2] 11 44 [2] 1e 5e [2] 00 43 [2] 02 42 [2] 19 44 [2] 05 43 [2] 19 6c }

  condition:
    any of them
}