rule TTP_XOR_QUAD_CurrentVersionRun_2f5d {
  strings:
    $key_2f5d = { 7c 32 [2] 58 3c [2] 73 10 [2] 5d 32 [2] 49 29 [2] 46 33 [2] 58 2e [2] 5a 2f [2] 41 29 [2] 5d 2e [2] 41 01 }

  condition:
    any of them
}