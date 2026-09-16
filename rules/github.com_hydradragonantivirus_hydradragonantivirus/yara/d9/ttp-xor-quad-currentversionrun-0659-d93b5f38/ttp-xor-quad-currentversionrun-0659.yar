rule TTP_XOR_QUAD_CurrentVersionRun_0659 {
  strings:
    $key_0659 = { 55 36 [2] 71 38 [2] 5a 14 [2] 74 36 [2] 60 2d [2] 6f 37 [2] 71 2a [2] 73 2b [2] 68 2d [2] 74 2a [2] 68 05 }

  condition:
    any of them
}