rule TTP_XOR_QUAD_CurrentVersionRun_6ce4 {
  strings:
    $key_6ce4 = { 3f 8b [2] 1b 85 [2] 30 a9 [2] 1e 8b [2] 0a 90 [2] 05 8a [2] 1b 97 [2] 19 96 [2] 02 90 [2] 1e 97 [2] 02 b8 }

  condition:
    any of them
}