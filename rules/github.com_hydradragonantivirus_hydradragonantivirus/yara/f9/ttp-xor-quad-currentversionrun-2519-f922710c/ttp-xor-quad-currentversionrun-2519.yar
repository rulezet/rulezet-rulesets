rule TTP_XOR_QUAD_CurrentVersionRun_2519 {
  strings:
    $key_2519 = { 76 76 [2] 52 78 [2] 79 54 [2] 57 76 [2] 43 6d [2] 4c 77 [2] 52 6a [2] 50 6b [2] 4b 6d [2] 57 6a [2] 4b 45 }

  condition:
    any of them
}