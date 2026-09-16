rule TTP_XOR_QUAD_CurrentVersionRun_4e45 {
  strings:
    $key_4e45 = { 1d 2a [2] 39 24 [2] 12 08 [2] 3c 2a [2] 28 31 [2] 27 2b [2] 39 36 [2] 3b 37 [2] 20 31 [2] 3c 36 [2] 20 19 }

  condition:
    any of them
}