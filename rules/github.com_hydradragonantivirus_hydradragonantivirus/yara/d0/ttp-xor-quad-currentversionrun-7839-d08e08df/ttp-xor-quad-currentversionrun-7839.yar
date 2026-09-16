rule TTP_XOR_QUAD_CurrentVersionRun_7839 {
  strings:
    $key_7839 = { 2b 56 [2] 0f 58 [2] 24 74 [2] 0a 56 [2] 1e 4d [2] 11 57 [2] 0f 4a [2] 0d 4b [2] 16 4d [2] 0a 4a [2] 16 65 }

  condition:
    any of them
}