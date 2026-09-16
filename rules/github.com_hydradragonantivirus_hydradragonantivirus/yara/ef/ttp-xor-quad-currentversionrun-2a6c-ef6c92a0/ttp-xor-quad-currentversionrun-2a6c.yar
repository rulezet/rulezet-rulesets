rule TTP_XOR_QUAD_CurrentVersionRun_2a6c {
  strings:
    $key_2a6c = { 79 03 [2] 5d 0d [2] 76 21 [2] 58 03 [2] 4c 18 [2] 43 02 [2] 5d 1f [2] 5f 1e [2] 44 18 [2] 58 1f [2] 44 30 }

  condition:
    any of them
}