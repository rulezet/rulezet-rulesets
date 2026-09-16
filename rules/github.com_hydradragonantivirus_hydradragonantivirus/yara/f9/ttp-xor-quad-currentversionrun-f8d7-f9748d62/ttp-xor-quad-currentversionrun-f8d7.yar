rule TTP_XOR_QUAD_CurrentVersionRun_f8d7 {
  strings:
    $key_f8d7 = { ab b8 [2] 8f b6 [2] a4 9a [2] 8a b8 [2] 9e a3 [2] 91 b9 [2] 8f a4 [2] 8d a5 [2] 96 a3 [2] 8a a4 [2] 96 8b }

  condition:
    any of them
}