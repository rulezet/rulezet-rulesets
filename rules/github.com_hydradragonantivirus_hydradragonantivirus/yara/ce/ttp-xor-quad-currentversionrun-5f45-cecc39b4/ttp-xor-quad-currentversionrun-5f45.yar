rule TTP_XOR_QUAD_CurrentVersionRun_5f45 {
  strings:
    $key_5f45 = { 0c 2a [2] 28 24 [2] 03 08 [2] 2d 2a [2] 39 31 [2] 36 2b [2] 28 36 [2] 2a 37 [2] 31 31 [2] 2d 36 [2] 31 19 }

  condition:
    any of them
}