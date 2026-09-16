rule TTP_XOR_QUAD_CurrentVersionRun_50c7 {
  strings:
    $key_50c7 = { 03 a8 [2] 27 a6 [2] 0c 8a [2] 22 a8 [2] 36 b3 [2] 39 a9 [2] 27 b4 [2] 25 b5 [2] 3e b3 [2] 22 b4 [2] 3e 9b }

  condition:
    any of them
}