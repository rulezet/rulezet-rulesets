rule TTP_XOR_QUAD_CurrentVersionRun_2730 {
  strings:
    $key_2730 = { 74 5f [2] 50 51 [2] 7b 7d [2] 55 5f [2] 41 44 [2] 4e 5e [2] 50 43 [2] 52 42 [2] 49 44 [2] 55 43 [2] 49 6c }

  condition:
    any of them
}