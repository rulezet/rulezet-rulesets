rule TTP_XOR_QUAD_CurrentVersionRun_0406 {
  strings:
    $key_0406 = { 57 69 [2] 73 67 [2] 58 4b [2] 76 69 [2] 62 72 [2] 6d 68 [2] 73 75 [2] 71 74 [2] 6a 72 [2] 76 75 [2] 6a 5a }

  condition:
    any of them
}