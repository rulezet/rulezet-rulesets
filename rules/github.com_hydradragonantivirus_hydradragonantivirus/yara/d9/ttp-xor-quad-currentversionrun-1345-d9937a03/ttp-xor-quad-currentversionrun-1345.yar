rule TTP_XOR_QUAD_CurrentVersionRun_1345 {
  strings:
    $key_1345 = { 40 2a [2] 64 24 [2] 4f 08 [2] 61 2a [2] 75 31 [2] 7a 2b [2] 64 36 [2] 66 37 [2] 7d 31 [2] 61 36 [2] 7d 19 }

  condition:
    any of them
}