rule TTP_XOR_QUAD_CurrentVersionRun_0b07 {
  strings:
    $key_0b07 = { 58 68 [2] 7c 66 [2] 57 4a [2] 79 68 [2] 6d 73 [2] 62 69 [2] 7c 74 [2] 7e 75 [2] 65 73 [2] 79 74 [2] 65 5b }

  condition:
    any of them
}