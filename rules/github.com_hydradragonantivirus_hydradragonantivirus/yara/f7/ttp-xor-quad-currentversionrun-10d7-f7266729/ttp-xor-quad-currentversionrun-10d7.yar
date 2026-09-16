rule TTP_XOR_QUAD_CurrentVersionRun_10d7 {
  strings:
    $key_10d7 = { 43 b8 [2] 67 b6 [2] 4c 9a [2] 62 b8 [2] 76 a3 [2] 79 b9 [2] 67 a4 [2] 65 a5 [2] 7e a3 [2] 62 a4 [2] 7e 8b }

  condition:
    any of them
}