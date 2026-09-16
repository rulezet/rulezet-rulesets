rule TTP_XOR_QUAD_CurrentVersionRun_2b50 {
  strings:
    $key_2b50 = { 78 3f [2] 5c 31 [2] 77 1d [2] 59 3f [2] 4d 24 [2] 42 3e [2] 5c 23 [2] 5e 22 [2] 45 24 [2] 59 23 [2] 45 0c }

  condition:
    any of them
}