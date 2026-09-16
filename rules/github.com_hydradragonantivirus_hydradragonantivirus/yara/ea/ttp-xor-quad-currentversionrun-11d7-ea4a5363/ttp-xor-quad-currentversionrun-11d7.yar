rule TTP_XOR_QUAD_CurrentVersionRun_11d7 {
  strings:
    $key_11d7 = { 42 b8 [2] 66 b6 [2] 4d 9a [2] 63 b8 [2] 77 a3 [2] 78 b9 [2] 66 a4 [2] 64 a5 [2] 7f a3 [2] 63 a4 [2] 7f 8b }

  condition:
    any of them
}