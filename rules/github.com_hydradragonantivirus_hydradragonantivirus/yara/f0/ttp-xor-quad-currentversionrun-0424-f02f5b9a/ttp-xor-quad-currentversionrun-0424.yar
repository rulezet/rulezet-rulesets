rule TTP_XOR_QUAD_CurrentVersionRun_0424 {
  strings:
    $key_0424 = { 57 4b [2] 73 45 [2] 58 69 [2] 76 4b [2] 62 50 [2] 6d 4a [2] 73 57 [2] 71 56 [2] 6a 50 [2] 76 57 [2] 6a 78 }

  condition:
    any of them
}