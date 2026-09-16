rule TTP_XOR_QUAD_CurrentVersionRun_2d4c {
  strings:
    $key_2d4c = { 7e 23 [2] 5a 2d [2] 71 01 [2] 5f 23 [2] 4b 38 [2] 44 22 [2] 5a 3f [2] 58 3e [2] 43 38 [2] 5f 3f [2] 43 10 }

  condition:
    any of them
}