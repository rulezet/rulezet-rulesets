rule TTP_XOR_QUAD_CurrentVersionRun_4e24 {
  strings:
    $key_4e24 = { 1d 4b [2] 39 45 [2] 12 69 [2] 3c 4b [2] 28 50 [2] 27 4a [2] 39 57 [2] 3b 56 [2] 20 50 [2] 3c 57 [2] 20 78 }

  condition:
    any of them
}