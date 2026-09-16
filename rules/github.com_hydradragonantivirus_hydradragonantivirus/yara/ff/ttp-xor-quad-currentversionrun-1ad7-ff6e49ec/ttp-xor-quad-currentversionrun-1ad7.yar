rule TTP_XOR_QUAD_CurrentVersionRun_1ad7 {
  strings:
    $key_1ad7 = { 49 b8 [2] 6d b6 [2] 46 9a [2] 68 b8 [2] 7c a3 [2] 73 b9 [2] 6d a4 [2] 6f a5 [2] 74 a3 [2] 68 a4 [2] 74 8b }

  condition:
    any of them
}