rule TTP_XOR_QUAD_CurrentVersionRun_4df8 {
  strings:
    $key_4df8 = { 1e 97 [2] 3a 99 [2] 11 b5 [2] 3f 97 [2] 2b 8c [2] 24 96 [2] 3a 8b [2] 38 8a [2] 23 8c [2] 3f 8b [2] 23 a4 }

  condition:
    any of them
}