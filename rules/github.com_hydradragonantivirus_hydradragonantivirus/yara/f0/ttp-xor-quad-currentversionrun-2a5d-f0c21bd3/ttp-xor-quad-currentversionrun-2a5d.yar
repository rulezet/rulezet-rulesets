rule TTP_XOR_QUAD_CurrentVersionRun_2a5d {
  strings:
    $key_2a5d = { 79 32 [2] 5d 3c [2] 76 10 [2] 58 32 [2] 4c 29 [2] 43 33 [2] 5d 2e [2] 5f 2f [2] 44 29 [2] 58 2e [2] 44 01 }

  condition:
    any of them
}