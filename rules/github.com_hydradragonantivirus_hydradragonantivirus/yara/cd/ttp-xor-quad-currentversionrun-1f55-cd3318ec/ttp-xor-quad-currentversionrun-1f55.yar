rule TTP_XOR_QUAD_CurrentVersionRun_1f55 {
  strings:
    $key_1f55 = { 4c 3a [2] 68 34 [2] 43 18 [2] 6d 3a [2] 79 21 [2] 76 3b [2] 68 26 [2] 6a 27 [2] 71 21 [2] 6d 26 [2] 71 09 }

  condition:
    any of them
}