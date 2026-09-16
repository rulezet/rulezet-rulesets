rule TTP_XOR_QUAD_CurrentVersionRun_7809 {
  strings:
    $key_7809 = { 2b 66 [2] 0f 68 [2] 24 44 [2] 0a 66 [2] 1e 7d [2] 11 67 [2] 0f 7a [2] 0d 7b [2] 16 7d [2] 0a 7a [2] 16 55 }

  condition:
    any of them
}