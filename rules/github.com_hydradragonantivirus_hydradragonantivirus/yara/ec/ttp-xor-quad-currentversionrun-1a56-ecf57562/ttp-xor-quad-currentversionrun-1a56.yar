rule TTP_XOR_QUAD_CurrentVersionRun_1a56 {
  strings:
    $key_1a56 = { 49 39 [2] 6d 37 [2] 46 1b [2] 68 39 [2] 7c 22 [2] 73 38 [2] 6d 25 [2] 6f 24 [2] 74 22 [2] 68 25 [2] 74 0a }

  condition:
    any of them
}