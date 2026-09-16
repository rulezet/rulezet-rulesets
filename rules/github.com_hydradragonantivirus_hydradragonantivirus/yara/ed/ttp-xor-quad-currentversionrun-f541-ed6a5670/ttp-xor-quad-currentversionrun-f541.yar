rule TTP_XOR_QUAD_CurrentVersionRun_f541 {
  strings:
    $key_f541 = { a6 2e [2] 82 20 [2] a9 0c [2] 87 2e [2] 93 35 [2] 9c 2f [2] 82 32 [2] 80 33 [2] 9b 35 [2] 87 32 [2] 9b 1d }

  condition:
    any of them
}