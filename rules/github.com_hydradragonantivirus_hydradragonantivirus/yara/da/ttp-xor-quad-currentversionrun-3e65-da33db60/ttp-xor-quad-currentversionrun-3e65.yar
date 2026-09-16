rule TTP_XOR_QUAD_CurrentVersionRun_3e65 {
  strings:
    $key_3e65 = { 6d 0a [2] 49 04 [2] 62 28 [2] 4c 0a [2] 58 11 [2] 57 0b [2] 49 16 [2] 4b 17 [2] 50 11 [2] 4c 16 [2] 50 39 }

  condition:
    any of them
}