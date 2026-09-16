rule TTP_XOR_QUAD_CurrentVersionRun_6324 {
  strings:
    $key_6324 = { 30 4b [2] 14 45 [2] 3f 69 [2] 11 4b [2] 05 50 [2] 0a 4a [2] 14 57 [2] 16 56 [2] 0d 50 [2] 11 57 [2] 0d 78 }

  condition:
    any of them
}