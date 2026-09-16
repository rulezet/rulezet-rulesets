rule TTP_XOR_QUAD_CurrentVersionRun_6307 {
  strings:
    $key_6307 = { 30 68 [2] 14 66 [2] 3f 4a [2] 11 68 [2] 05 73 [2] 0a 69 [2] 14 74 [2] 16 75 [2] 0d 73 [2] 11 74 [2] 0d 5b }

  condition:
    any of them
}