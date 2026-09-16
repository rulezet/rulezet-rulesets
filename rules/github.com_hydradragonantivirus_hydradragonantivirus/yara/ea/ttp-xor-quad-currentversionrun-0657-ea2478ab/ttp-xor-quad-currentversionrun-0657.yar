rule TTP_XOR_QUAD_CurrentVersionRun_0657 {
  strings:
    $key_0657 = { 55 38 [2] 71 36 [2] 5a 1a [2] 74 38 [2] 60 23 [2] 6f 39 [2] 71 24 [2] 73 25 [2] 68 23 [2] 74 24 [2] 68 0b }

  condition:
    any of them
}