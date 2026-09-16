rule TTP_XOR_QUAD_CurrentVersionRun_06e4 {
  strings:
    $key_06e4 = { 55 8b [2] 71 85 [2] 5a a9 [2] 74 8b [2] 60 90 [2] 6f 8a [2] 71 97 [2] 73 96 [2] 68 90 [2] 74 97 [2] 68 b8 }

  condition:
    any of them
}