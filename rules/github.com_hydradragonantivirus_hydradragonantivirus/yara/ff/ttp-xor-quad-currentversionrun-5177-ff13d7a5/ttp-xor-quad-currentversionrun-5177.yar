rule TTP_XOR_QUAD_CurrentVersionRun_5177 {
  strings:
    $key_5177 = { 02 18 [2] 26 16 [2] 0d 3a [2] 23 18 [2] 37 03 [2] 38 19 [2] 26 04 [2] 24 05 [2] 3f 03 [2] 23 04 [2] 3f 2b }

  condition:
    any of them
}