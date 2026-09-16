rule TTP_XOR_QUAD_CurrentVersionRun_46d6 {
  strings:
    $key_46d6 = { 15 b9 [2] 31 b7 [2] 1a 9b [2] 34 b9 [2] 20 a2 [2] 2f b8 [2] 31 a5 [2] 33 a4 [2] 28 a2 [2] 34 a5 [2] 28 8a }

  condition:
    any of them
}