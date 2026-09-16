rule TTP_XOR_QUAD_CurrentVersionRun_0656 {
  strings:
    $key_0656 = { 55 39 [2] 71 37 [2] 5a 1b [2] 74 39 [2] 60 22 [2] 6f 38 [2] 71 25 [2] 73 24 [2] 68 22 [2] 74 25 [2] 68 0a }

  condition:
    any of them
}