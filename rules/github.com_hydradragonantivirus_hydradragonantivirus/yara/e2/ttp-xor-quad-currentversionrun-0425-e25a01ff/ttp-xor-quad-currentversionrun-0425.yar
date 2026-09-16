rule TTP_XOR_QUAD_CurrentVersionRun_0425 {
  strings:
    $key_0425 = { 57 4a [2] 73 44 [2] 58 68 [2] 76 4a [2] 62 51 [2] 6d 4b [2] 73 56 [2] 71 57 [2] 6a 51 [2] 76 56 [2] 6a 79 }

  condition:
    any of them
}