rule TTP_XOR_QUAD_CurrentVersionRun_2afd {
  strings:
    $key_2afd = { 79 92 [2] 5d 9c [2] 76 b0 [2] 58 92 [2] 4c 89 [2] 43 93 [2] 5d 8e [2] 5f 8f [2] 44 89 [2] 58 8e [2] 44 a1 }

  condition:
    any of them
}