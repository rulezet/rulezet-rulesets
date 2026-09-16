rule TTP_XOR_QUAD_CurrentVersionRun_26d6 {
  strings:
    $key_26d6 = { 75 b9 [2] 51 b7 [2] 7a 9b [2] 54 b9 [2] 40 a2 [2] 4f b8 [2] 51 a5 [2] 53 a4 [2] 48 a2 [2] 54 a5 [2] 48 8a }

  condition:
    any of them
}