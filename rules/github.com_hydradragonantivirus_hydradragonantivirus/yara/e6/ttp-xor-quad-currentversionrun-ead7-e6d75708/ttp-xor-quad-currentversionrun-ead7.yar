rule TTP_XOR_QUAD_CurrentVersionRun_ead7 {
  strings:
    $key_ead7 = { b9 b8 [2] 9d b6 [2] b6 9a [2] 98 b8 [2] 8c a3 [2] 83 b9 [2] 9d a4 [2] 9f a5 [2] 84 a3 [2] 98 a4 [2] 84 8b }

  condition:
    any of them
}