rule TTP_XOR_QUAD_CurrentVersionRun_6339 {
  strings:
    $key_6339 = { 30 56 [2] 14 58 [2] 3f 74 [2] 11 56 [2] 05 4d [2] 0a 57 [2] 14 4a [2] 16 4b [2] 0d 4d [2] 11 4a [2] 0d 65 }

  condition:
    any of them
}