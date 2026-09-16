rule TTP_XOR_QUAD_CurrentVersionRun_2250 {
  strings:
    $key_2250 = { 71 3f [2] 55 31 [2] 7e 1d [2] 50 3f [2] 44 24 [2] 4b 3e [2] 55 23 [2] 57 22 [2] 4c 24 [2] 50 23 [2] 4c 0c }

  condition:
    any of them
}