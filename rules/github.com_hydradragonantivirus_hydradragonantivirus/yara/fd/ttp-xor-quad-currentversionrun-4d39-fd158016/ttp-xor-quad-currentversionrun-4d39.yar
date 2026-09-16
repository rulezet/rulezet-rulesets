rule TTP_XOR_QUAD_CurrentVersionRun_4d39 {
  strings:
    $key_4d39 = { 1e 56 [2] 3a 58 [2] 11 74 [2] 3f 56 [2] 2b 4d [2] 24 57 [2] 3a 4a [2] 38 4b [2] 23 4d [2] 3f 4a [2] 23 65 }

  condition:
    any of them
}