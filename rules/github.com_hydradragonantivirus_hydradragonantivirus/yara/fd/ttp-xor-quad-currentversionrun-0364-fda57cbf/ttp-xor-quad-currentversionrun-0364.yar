rule TTP_XOR_QUAD_CurrentVersionRun_0364 {
  strings:
    $key_0364 = { 50 0b [2] 74 05 [2] 5f 29 [2] 71 0b [2] 65 10 [2] 6a 0a [2] 74 17 [2] 76 16 [2] 6d 10 [2] 71 17 [2] 6d 38 }

  condition:
    any of them
}