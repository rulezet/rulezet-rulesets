rule TTP_XOR_QUAD_CurrentVersionRun_5a6b {
  strings:
    $key_5a6b = { 09 04 [2] 2d 0a [2] 06 26 [2] 28 04 [2] 3c 1f [2] 33 05 [2] 2d 18 [2] 2f 19 [2] 34 1f [2] 28 18 [2] 34 37 }

  condition:
    any of them
}