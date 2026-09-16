rule TTP_XOR_QUAD_CurrentVersionRun_564b {
  strings:
    $key_564b = { 05 24 [2] 21 2a [2] 0a 06 [2] 24 24 [2] 30 3f [2] 3f 25 [2] 21 38 [2] 23 39 [2] 38 3f [2] 24 38 [2] 38 17 }

  condition:
    any of them
}