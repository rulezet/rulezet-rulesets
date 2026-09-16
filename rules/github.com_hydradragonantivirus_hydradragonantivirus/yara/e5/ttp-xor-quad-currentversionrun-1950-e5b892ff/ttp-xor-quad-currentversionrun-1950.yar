rule TTP_XOR_QUAD_CurrentVersionRun_1950 {
  strings:
    $key_1950 = { 4a 3f [2] 6e 31 [2] 45 1d [2] 6b 3f [2] 7f 24 [2] 70 3e [2] 6e 23 [2] 6c 22 [2] 77 24 [2] 6b 23 [2] 77 0c }

  condition:
    any of them
}