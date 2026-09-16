rule TTP_XOR_QUAD_CurrentVersionRun_0774 {
  strings:
    $key_0774 = { 54 1b [2] 70 15 [2] 5b 39 [2] 75 1b [2] 61 00 [2] 6e 1a [2] 70 07 [2] 72 06 [2] 69 00 [2] 75 07 [2] 69 28 }

  condition:
    any of them
}