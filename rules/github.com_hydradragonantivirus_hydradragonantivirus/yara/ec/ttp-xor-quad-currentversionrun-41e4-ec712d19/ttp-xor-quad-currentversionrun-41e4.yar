rule TTP_XOR_QUAD_CurrentVersionRun_41e4 {
  strings:
    $key_41e4 = { 12 8b [2] 36 85 [2] 1d a9 [2] 33 8b [2] 27 90 [2] 28 8a [2] 36 97 [2] 34 96 [2] 2f 90 [2] 33 97 [2] 2f b8 }

  condition:
    any of them
}