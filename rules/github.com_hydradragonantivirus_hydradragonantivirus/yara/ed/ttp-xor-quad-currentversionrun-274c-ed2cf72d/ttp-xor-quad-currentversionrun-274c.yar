rule TTP_XOR_QUAD_CurrentVersionRun_274c {
  strings:
    $key_274c = { 74 23 [2] 50 2d [2] 7b 01 [2] 55 23 [2] 41 38 [2] 4e 22 [2] 50 3f [2] 52 3e [2] 49 38 [2] 55 3f [2] 49 10 }

  condition:
    any of them
}