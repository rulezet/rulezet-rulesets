rule TTP_XOR_QUAD_CurrentVersionRun_0e06 {
  strings:
    $key_0e06 = { 5d 69 [2] 79 67 [2] 52 4b [2] 7c 69 [2] 68 72 [2] 67 68 [2] 79 75 [2] 7b 74 [2] 60 72 [2] 7c 75 [2] 60 5a }

  condition:
    any of them
}