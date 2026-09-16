rule TTP_XOR_QUAD_CurrentVersionRun_0345 {
  strings:
    $key_0345 = { 50 2a [2] 74 24 [2] 5f 08 [2] 71 2a [2] 65 31 [2] 6a 2b [2] 74 36 [2] 76 37 [2] 6d 31 [2] 71 36 [2] 6d 19 }

  condition:
    any of them
}