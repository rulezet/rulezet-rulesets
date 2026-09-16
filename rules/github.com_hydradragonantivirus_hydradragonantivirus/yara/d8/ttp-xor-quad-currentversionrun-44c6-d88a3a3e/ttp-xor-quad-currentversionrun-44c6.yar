rule TTP_XOR_QUAD_CurrentVersionRun_44c6 {
  strings:
    $key_44c6 = { 17 a9 [2] 33 a7 [2] 18 8b [2] 36 a9 [2] 22 b2 [2] 2d a8 [2] 33 b5 [2] 31 b4 [2] 2a b2 [2] 36 b5 [2] 2a 9a }

  condition:
    any of them
}