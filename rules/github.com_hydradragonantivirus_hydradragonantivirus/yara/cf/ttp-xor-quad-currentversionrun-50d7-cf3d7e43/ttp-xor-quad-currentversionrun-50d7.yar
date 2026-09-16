rule TTP_XOR_QUAD_CurrentVersionRun_50d7 {
  strings:
    $key_50d7 = { 03 b8 [2] 27 b6 [2] 0c 9a [2] 22 b8 [2] 36 a3 [2] 39 b9 [2] 27 a4 [2] 25 a5 [2] 3e a3 [2] 22 a4 [2] 3e 8b }

  condition:
    any of them
}