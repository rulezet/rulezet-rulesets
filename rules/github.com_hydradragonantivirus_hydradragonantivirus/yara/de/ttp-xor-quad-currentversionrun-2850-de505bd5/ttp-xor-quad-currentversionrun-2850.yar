rule TTP_XOR_QUAD_CurrentVersionRun_2850 {
  strings:
    $key_2850 = { 7b 3f [2] 5f 31 [2] 74 1d [2] 5a 3f [2] 4e 24 [2] 41 3e [2] 5f 23 [2] 5d 22 [2] 46 24 [2] 5a 23 [2] 46 0c }

  condition:
    any of them
}