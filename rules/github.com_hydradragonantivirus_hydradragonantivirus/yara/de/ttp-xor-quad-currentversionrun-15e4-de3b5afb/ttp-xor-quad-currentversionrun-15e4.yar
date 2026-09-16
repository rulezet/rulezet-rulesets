rule TTP_XOR_QUAD_CurrentVersionRun_15e4 {
  strings:
    $key_15e4 = { 46 8b [2] 62 85 [2] 49 a9 [2] 67 8b [2] 73 90 [2] 7c 8a [2] 62 97 [2] 60 96 [2] 7b 90 [2] 67 97 [2] 7b b8 }

  condition:
    any of them
}