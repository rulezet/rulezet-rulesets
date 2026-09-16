rule TTP_XOR_QUAD_CurrentVersionRun_4d78 {
  strings:
    $key_4d78 = { 1e 17 [2] 3a 19 [2] 11 35 [2] 3f 17 [2] 2b 0c [2] 24 16 [2] 3a 0b [2] 38 0a [2] 23 0c [2] 3f 0b [2] 23 24 }

  condition:
    any of them
}