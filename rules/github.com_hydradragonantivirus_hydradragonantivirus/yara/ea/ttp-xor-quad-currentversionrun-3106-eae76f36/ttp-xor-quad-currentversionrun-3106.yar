rule TTP_XOR_QUAD_CurrentVersionRun_3106 {
  strings:
    $key_3106 = { 62 69 [2] 46 67 [2] 6d 4b [2] 43 69 [2] 57 72 [2] 58 68 [2] 46 75 [2] 44 74 [2] 5f 72 [2] 43 75 [2] 5f 5a }

  condition:
    any of them
}