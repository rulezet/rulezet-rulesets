rule TTP_XOR_QUAD_CurrentVersionRun_0427 {
  strings:
    $key_0427 = { 57 48 [2] 73 46 [2] 58 6a [2] 76 48 [2] 62 53 [2] 6d 49 [2] 73 54 [2] 71 55 [2] 6a 53 [2] 76 54 [2] 6a 7b }

  condition:
    any of them
}