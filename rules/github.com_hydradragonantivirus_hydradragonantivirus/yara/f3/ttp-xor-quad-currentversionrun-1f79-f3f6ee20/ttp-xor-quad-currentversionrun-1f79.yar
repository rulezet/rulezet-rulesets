rule TTP_XOR_QUAD_CurrentVersionRun_1f79 {
  strings:
    $key_1f79 = { 4c 16 [2] 68 18 [2] 43 34 [2] 6d 16 [2] 79 0d [2] 76 17 [2] 68 0a [2] 6a 0b [2] 71 0d [2] 6d 0a [2] 71 25 }

  condition:
    any of them
}