rule TTP_XOR_QUAD_CurrentVersionRun_0435 {
  strings:
    $key_0435 = { 57 5a [2] 73 54 [2] 58 78 [2] 76 5a [2] 62 41 [2] 6d 5b [2] 73 46 [2] 71 47 [2] 6a 41 [2] 76 46 [2] 6a 69 }

  condition:
    any of them
}