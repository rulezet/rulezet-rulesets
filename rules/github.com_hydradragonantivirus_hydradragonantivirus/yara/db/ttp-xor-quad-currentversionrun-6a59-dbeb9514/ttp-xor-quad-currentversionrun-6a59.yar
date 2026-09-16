rule TTP_XOR_QUAD_CurrentVersionRun_6a59 {
  strings:
    $key_6a59 = { 39 36 [2] 1d 38 [2] 36 14 [2] 18 36 [2] 0c 2d [2] 03 37 [2] 1d 2a [2] 1f 2b [2] 04 2d [2] 18 2a [2] 04 05 }

  condition:
    any of them
}