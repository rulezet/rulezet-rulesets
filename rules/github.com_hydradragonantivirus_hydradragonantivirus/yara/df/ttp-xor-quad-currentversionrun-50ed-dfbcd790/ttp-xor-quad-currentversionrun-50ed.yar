rule TTP_XOR_QUAD_CurrentVersionRun_50ed {
  strings:
    $key_50ed = { 03 82 [2] 27 8c [2] 0c a0 [2] 22 82 [2] 36 99 [2] 39 83 [2] 27 9e [2] 25 9f [2] 3e 99 [2] 22 9e [2] 3e b1 }

  condition:
    any of them
}