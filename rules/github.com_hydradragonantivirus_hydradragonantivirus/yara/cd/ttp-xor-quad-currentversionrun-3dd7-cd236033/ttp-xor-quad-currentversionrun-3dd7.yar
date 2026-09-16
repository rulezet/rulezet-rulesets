rule TTP_XOR_QUAD_CurrentVersionRun_3dd7 {
  strings:
    $key_3dd7 = { 6e b8 [2] 4a b6 [2] 61 9a [2] 4f b8 [2] 5b a3 [2] 54 b9 [2] 4a a4 [2] 48 a5 [2] 53 a3 [2] 4f a4 [2] 53 8b }

  condition:
    any of them
}