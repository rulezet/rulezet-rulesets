rule TTP_XOR_QUAD_CurrentVersionRun_1a47 {
  strings:
    $key_1a47 = { 49 28 [2] 6d 26 [2] 46 0a [2] 68 28 [2] 7c 33 [2] 73 29 [2] 6d 34 [2] 6f 35 [2] 74 33 [2] 68 34 [2] 74 1b }

  condition:
    any of them
}