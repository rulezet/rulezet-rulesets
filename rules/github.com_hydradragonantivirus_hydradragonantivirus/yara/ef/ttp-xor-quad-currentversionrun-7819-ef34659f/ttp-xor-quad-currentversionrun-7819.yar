rule TTP_XOR_QUAD_CurrentVersionRun_7819 {
  strings:
    $key_7819 = { 2b 76 [2] 0f 78 [2] 24 54 [2] 0a 76 [2] 1e 6d [2] 11 77 [2] 0f 6a [2] 0d 6b [2] 16 6d [2] 0a 6a [2] 16 45 }

  condition:
    any of them
}