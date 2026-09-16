rule TTP_XOR_QUAD_CurrentVersionRun_0368 {
  strings:
    $key_0368 = { 50 07 [2] 74 09 [2] 5f 25 [2] 71 07 [2] 65 1c [2] 6a 06 [2] 74 1b [2] 76 1a [2] 6d 1c [2] 71 1b [2] 6d 34 }

  condition:
    any of them
}