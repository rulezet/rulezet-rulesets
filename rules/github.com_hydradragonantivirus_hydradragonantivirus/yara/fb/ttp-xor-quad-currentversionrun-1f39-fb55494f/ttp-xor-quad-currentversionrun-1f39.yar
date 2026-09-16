rule TTP_XOR_QUAD_CurrentVersionRun_1f39 {
  strings:
    $key_1f39 = { 4c 56 [2] 68 58 [2] 43 74 [2] 6d 56 [2] 79 4d [2] 76 57 [2] 68 4a [2] 6a 4b [2] 71 4d [2] 6d 4a [2] 71 65 }

  condition:
    any of them
}