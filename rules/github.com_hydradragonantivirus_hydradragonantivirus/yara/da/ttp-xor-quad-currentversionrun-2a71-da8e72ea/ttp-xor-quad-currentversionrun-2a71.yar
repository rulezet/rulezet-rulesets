rule TTP_XOR_QUAD_CurrentVersionRun_2a71 {
  strings:
    $key_2a71 = { 79 1e [2] 5d 10 [2] 76 3c [2] 58 1e [2] 4c 05 [2] 43 1f [2] 5d 02 [2] 5f 03 [2] 44 05 [2] 58 02 [2] 44 2d }

  condition:
    any of them
}