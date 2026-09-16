rule TTP_XOR_QUAD_CurrentVersionRun_2f5c {
  strings:
    $key_2f5c = { 7c 33 [2] 58 3d [2] 73 11 [2] 5d 33 [2] 49 28 [2] 46 32 [2] 58 2f [2] 5a 2e [2] 41 28 [2] 5d 2f [2] 41 00 }

  condition:
    any of them
}