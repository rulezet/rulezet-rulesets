rule TTP_XOR_QUAD_CurrentVersionRun_0679 {
  strings:
    $key_0679 = { 55 16 [2] 71 18 [2] 5a 34 [2] 74 16 [2] 60 0d [2] 6f 17 [2] 71 0a [2] 73 0b [2] 68 0d [2] 74 0a [2] 68 25 }

  condition:
    any of them
}