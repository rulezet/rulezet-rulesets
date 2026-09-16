rule TTP_XOR_QUAD_CurrentVersionRun_3e06 {
  strings:
    $key_3e06 = { 6d 69 [2] 49 67 [2] 62 4b [2] 4c 69 [2] 58 72 [2] 57 68 [2] 49 75 [2] 4b 74 [2] 50 72 [2] 4c 75 [2] 50 5a }

  condition:
    any of them
}