rule TTP_XOR_QUAD_CurrentVersionRun_0319 {
  strings:
    $key_0319 = { 50 76 [2] 74 78 [2] 5f 54 [2] 71 76 [2] 65 6d [2] 6a 77 [2] 74 6a [2] 76 6b [2] 6d 6d [2] 71 6a [2] 6d 45 }

  condition:
    any of them
}