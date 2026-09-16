rule TTP_XOR_QUAD_CurrentVersionRun_0647 {
  strings:
    $key_0647 = { 55 28 [2] 71 26 [2] 5a 0a [2] 74 28 [2] 60 33 [2] 6f 29 [2] 71 34 [2] 73 35 [2] 68 33 [2] 74 34 [2] 68 1b }

  condition:
    any of them
}