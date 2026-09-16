rule TTP_XOR_QUAD_CurrentVersionRun_f5ec {
  strings:
    $key_f5ec = { a6 83 [2] 82 8d [2] a9 a1 [2] 87 83 [2] 93 98 [2] 9c 82 [2] 82 9f [2] 80 9e [2] 9b 98 [2] 87 9f [2] 9b b0 }

  condition:
    any of them
}