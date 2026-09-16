rule TTP_XOR_QUAD_CurrentVersionRun_2b30 {
  strings:
    $key_2b30 = { 78 5f [2] 5c 51 [2] 77 7d [2] 59 5f [2] 4d 44 [2] 42 5e [2] 5c 43 [2] 5e 42 [2] 45 44 [2] 59 43 [2] 45 6c }

  condition:
    any of them
}