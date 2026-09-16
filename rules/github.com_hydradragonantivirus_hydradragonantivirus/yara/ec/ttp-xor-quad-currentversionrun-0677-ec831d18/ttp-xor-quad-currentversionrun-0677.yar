rule TTP_XOR_QUAD_CurrentVersionRun_0677 {
  strings:
    $key_0677 = { 55 18 [2] 71 16 [2] 5a 3a [2] 74 18 [2] 60 03 [2] 6f 19 [2] 71 04 [2] 73 05 [2] 68 03 [2] 74 04 [2] 68 2b }

  condition:
    any of them
}