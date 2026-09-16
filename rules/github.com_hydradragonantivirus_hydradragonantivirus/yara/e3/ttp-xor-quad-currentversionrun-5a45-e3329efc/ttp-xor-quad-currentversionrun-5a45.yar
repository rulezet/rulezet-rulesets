rule TTP_XOR_QUAD_CurrentVersionRun_5a45 {
  strings:
    $key_5a45 = { 09 2a [2] 2d 24 [2] 06 08 [2] 28 2a [2] 3c 31 [2] 33 2b [2] 2d 36 [2] 2f 37 [2] 34 31 [2] 28 36 [2] 34 19 }

  condition:
    any of them
}