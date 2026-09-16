rule TTP_XOR_QUAD_CurrentVersionRun_0e37 {
  strings:
    $key_0e37 = { 5d 58 [2] 79 56 [2] 52 7a [2] 7c 58 [2] 68 43 [2] 67 59 [2] 79 44 [2] 7b 45 [2] 60 43 [2] 7c 44 [2] 60 6b }

  condition:
    any of them
}