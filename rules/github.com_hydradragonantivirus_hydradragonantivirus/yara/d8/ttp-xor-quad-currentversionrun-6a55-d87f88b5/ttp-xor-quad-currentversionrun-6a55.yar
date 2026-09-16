rule TTP_XOR_QUAD_CurrentVersionRun_6a55 {
  strings:
    $key_6a55 = { 39 3a [2] 1d 34 [2] 36 18 [2] 18 3a [2] 0c 21 [2] 03 3b [2] 1d 26 [2] 1f 27 [2] 04 21 [2] 18 26 [2] 04 09 }

  condition:
    any of them
}