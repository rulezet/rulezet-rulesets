rule TTP_XOR_QUAD_CurrentVersionRun_4d24 {
  strings:
    $key_4d24 = { 1e 4b [2] 3a 45 [2] 11 69 [2] 3f 4b [2] 2b 50 [2] 24 4a [2] 3a 57 [2] 38 56 [2] 23 50 [2] 3f 57 [2] 23 78 }

  condition:
    any of them
}