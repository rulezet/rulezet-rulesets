rule TTP_XOR_QUAD_CurrentVersionRun_2f4d {
  strings:
    $key_2f4d = { 7c 22 [2] 58 2c [2] 73 00 [2] 5d 22 [2] 49 39 [2] 46 23 [2] 58 3e [2] 5a 3f [2] 41 39 [2] 5d 3e [2] 41 11 }

  condition:
    any of them
}