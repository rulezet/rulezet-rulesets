rule TTP_XOR_QUAD_CurrentVersionRun_1f65 {
  strings:
    $key_1f65 = { 4c 0a [2] 68 04 [2] 43 28 [2] 6d 0a [2] 79 11 [2] 76 0b [2] 68 16 [2] 6a 17 [2] 71 11 [2] 6d 16 [2] 71 39 }

  condition:
    any of them
}