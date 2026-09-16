rule TTP_XOR_QUAD_CurrentVersionRun_20e4 {
  strings:
    $key_20e4 = { 73 8b [2] 57 85 [2] 7c a9 [2] 52 8b [2] 46 90 [2] 49 8a [2] 57 97 [2] 55 96 [2] 4e 90 [2] 52 97 [2] 4e b8 }

  condition:
    any of them
}