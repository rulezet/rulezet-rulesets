rule TTP_XOR_QUAD_CurrentVersionRun_3407 {
  strings:
    $key_3407 = { 67 68 [2] 43 66 [2] 68 4a [2] 46 68 [2] 52 73 [2] 5d 69 [2] 43 74 [2] 41 75 [2] 5a 73 [2] 46 74 [2] 5a 5b }

  condition:
    any of them
}