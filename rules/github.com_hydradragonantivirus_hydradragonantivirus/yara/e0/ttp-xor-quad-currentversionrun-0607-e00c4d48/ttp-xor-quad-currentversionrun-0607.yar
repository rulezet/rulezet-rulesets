rule TTP_XOR_QUAD_CurrentVersionRun_0607 {
  strings:
    $key_0607 = { 55 68 [2] 71 66 [2] 5a 4a [2] 74 68 [2] 60 73 [2] 6f 69 [2] 71 74 [2] 73 75 [2] 68 73 [2] 74 74 [2] 68 5b }

  condition:
    any of them
}