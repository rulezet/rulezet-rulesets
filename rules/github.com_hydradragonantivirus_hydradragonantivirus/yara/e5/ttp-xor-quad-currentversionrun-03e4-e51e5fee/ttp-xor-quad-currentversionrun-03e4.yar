rule TTP_XOR_QUAD_CurrentVersionRun_03e4 {
  strings:
    $key_03e4 = { 50 8b [2] 74 85 [2] 5f a9 [2] 71 8b [2] 65 90 [2] 6a 8a [2] 74 97 [2] 76 96 [2] 6d 90 [2] 71 97 [2] 6d b8 }

  condition:
    any of them
}