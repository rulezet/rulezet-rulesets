rule TTP_XOR_QUAD_CurrentVersionRun_4d45 {
  strings:
    $key_4d45 = { 1e 2a [2] 3a 24 [2] 11 08 [2] 3f 2a [2] 2b 31 [2] 24 2b [2] 3a 36 [2] 38 37 [2] 23 31 [2] 3f 36 [2] 23 19 }

  condition:
    any of them
}