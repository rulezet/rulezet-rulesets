rule TTP_XOR_QUAD_CurrentVersionRun_684b {
  strings:
    $key_684b = { 3b 24 [2] 1f 2a [2] 34 06 [2] 1a 24 [2] 0e 3f [2] 01 25 [2] 1f 38 [2] 1d 39 [2] 06 3f [2] 1a 38 [2] 06 17 }

  condition:
    any of them
}