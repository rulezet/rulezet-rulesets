rule TTP_XOR_QUAD_CurrentVersionRun_7b30 {
  strings:
    $key_7b30 = { 28 5f [2] 0c 51 [2] 27 7d [2] 09 5f [2] 1d 44 [2] 12 5e [2] 0c 43 [2] 0e 42 [2] 15 44 [2] 09 43 [2] 15 6c }

  condition:
    any of them
}