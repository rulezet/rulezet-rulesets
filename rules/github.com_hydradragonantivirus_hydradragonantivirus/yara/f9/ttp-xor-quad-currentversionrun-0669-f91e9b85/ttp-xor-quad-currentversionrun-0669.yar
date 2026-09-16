rule TTP_XOR_QUAD_CurrentVersionRun_0669 {
  strings:
    $key_0669 = { 55 06 [2] 71 08 [2] 5a 24 [2] 74 06 [2] 60 1d [2] 6f 07 [2] 71 1a [2] 73 1b [2] 68 1d [2] 74 1a [2] 68 35 }

  condition:
    any of them
}