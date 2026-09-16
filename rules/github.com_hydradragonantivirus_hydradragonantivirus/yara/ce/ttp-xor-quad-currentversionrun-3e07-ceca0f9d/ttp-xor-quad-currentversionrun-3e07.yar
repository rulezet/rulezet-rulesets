rule TTP_XOR_QUAD_CurrentVersionRun_3e07 {
  strings:
    $key_3e07 = { 6d 68 [2] 49 66 [2] 62 4a [2] 4c 68 [2] 58 73 [2] 57 69 [2] 49 74 [2] 4b 75 [2] 50 73 [2] 4c 74 [2] 50 5b }

  condition:
    any of them
}