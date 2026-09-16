rule TTP_XOR_QUAD_CurrentVersionRun_2f4c {
  strings:
    $key_2f4c = { 7c 23 [2] 58 2d [2] 73 01 [2] 5d 23 [2] 49 38 [2] 46 22 [2] 58 3f [2] 5a 3e [2] 41 38 [2] 5d 3f [2] 41 10 }

  condition:
    any of them
}