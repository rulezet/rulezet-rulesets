rule TTP_XOR_QUAD_CurrentVersionRun_e8d6 {
  strings:
    $key_e8d6 = { bb b9 [2] 9f b7 [2] b4 9b [2] 9a b9 [2] 8e a2 [2] 81 b8 [2] 9f a5 [2] 9d a4 [2] 86 a2 [2] 9a a5 [2] 86 8a }

  condition:
    any of them
}