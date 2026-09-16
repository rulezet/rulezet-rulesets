rule TTP_XOR_QUAD_CurrentVersionRun_3605 {
  strings:
    $key_3605 = { 65 6a [2] 41 64 [2] 6a 48 [2] 44 6a [2] 50 71 [2] 5f 6b [2] 41 76 [2] 43 77 [2] 58 71 [2] 44 76 [2] 58 59 }

  condition:
    any of them
}