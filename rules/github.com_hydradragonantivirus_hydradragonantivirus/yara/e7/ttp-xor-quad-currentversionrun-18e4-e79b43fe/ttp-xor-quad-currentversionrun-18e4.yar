rule TTP_XOR_QUAD_CurrentVersionRun_18e4 {
  strings:
    $key_18e4 = { 4b 8b [2] 6f 85 [2] 44 a9 [2] 6a 8b [2] 7e 90 [2] 71 8a [2] 6f 97 [2] 6d 96 [2] 76 90 [2] 6a 97 [2] 76 b8 }

  condition:
    any of them
}