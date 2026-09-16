rule TTP_XOR_QUAD_CurrentVersionRun_2b23 {
  strings:
    $key_2b23 = { 78 4c [2] 5c 42 [2] 77 6e [2] 59 4c [2] 4d 57 [2] 42 4d [2] 5c 50 [2] 5e 51 [2] 45 57 [2] 59 50 [2] 45 7f }

  condition:
    any of them
}