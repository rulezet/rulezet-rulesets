rule TTP_XOR_QUAD_CurrentVersionRun_0654 {
  strings:
    $key_0654 = { 55 3b [2] 71 35 [2] 5a 19 [2] 74 3b [2] 60 20 [2] 6f 3a [2] 71 27 [2] 73 26 [2] 68 20 [2] 74 27 [2] 68 08 }

  condition:
    any of them
}