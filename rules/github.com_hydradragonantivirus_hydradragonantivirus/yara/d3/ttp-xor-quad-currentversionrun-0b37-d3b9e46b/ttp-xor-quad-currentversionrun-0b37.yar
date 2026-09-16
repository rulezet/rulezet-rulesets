rule TTP_XOR_QUAD_CurrentVersionRun_0b37 {
  strings:
    $key_0b37 = { 58 58 [2] 7c 56 [2] 57 7a [2] 79 58 [2] 6d 43 [2] 62 59 [2] 7c 44 [2] 7e 45 [2] 65 43 [2] 79 44 [2] 65 6b }

  condition:
    any of them
}