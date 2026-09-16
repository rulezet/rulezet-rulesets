rule TTP_XOR_QUAD_CurrentVersionRun_1324 {
  strings:
    $key_1324 = { 40 4b [2] 64 45 [2] 4f 69 [2] 61 4b [2] 75 50 [2] 7a 4a [2] 64 57 [2] 66 56 [2] 7d 50 [2] 61 57 [2] 7d 78 }

  condition:
    any of them
}