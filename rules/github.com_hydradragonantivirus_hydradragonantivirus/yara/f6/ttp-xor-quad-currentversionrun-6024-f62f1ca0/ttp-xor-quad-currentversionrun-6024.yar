rule TTP_XOR_QUAD_CurrentVersionRun_6024 {
  strings:
    $key_6024 = { 33 4b [2] 17 45 [2] 3c 69 [2] 12 4b [2] 06 50 [2] 09 4a [2] 17 57 [2] 15 56 [2] 0e 50 [2] 12 57 [2] 0e 78 }

  condition:
    any of them
}