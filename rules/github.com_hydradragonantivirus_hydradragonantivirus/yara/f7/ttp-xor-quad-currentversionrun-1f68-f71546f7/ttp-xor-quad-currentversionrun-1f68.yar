rule TTP_XOR_QUAD_CurrentVersionRun_1f68 {
  strings:
    $key_1f68 = { 4c 07 [2] 68 09 [2] 43 25 [2] 6d 07 [2] 79 1c [2] 76 06 [2] 68 1b [2] 6a 1a [2] 71 1c [2] 6d 1b [2] 71 34 }

  condition:
    any of them
}