rule TTP_XOR_QUAD_CurrentVersionRun_1319 {
  strings:
    $key_1319 = { 40 76 [2] 64 78 [2] 4f 54 [2] 61 76 [2] 75 6d [2] 7a 77 [2] 64 6a [2] 66 6b [2] 7d 6d [2] 61 6a [2] 7d 45 }

  condition:
    any of them
}