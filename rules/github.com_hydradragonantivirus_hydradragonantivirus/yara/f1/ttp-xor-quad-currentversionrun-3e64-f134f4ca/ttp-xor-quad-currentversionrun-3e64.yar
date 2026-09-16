rule TTP_XOR_QUAD_CurrentVersionRun_3e64 {
  strings:
    $key_3e64 = { 6d 0b [2] 49 05 [2] 62 29 [2] 4c 0b [2] 58 10 [2] 57 0a [2] 49 17 [2] 4b 16 [2] 50 10 [2] 4c 17 [2] 50 38 }

  condition:
    any of them
}