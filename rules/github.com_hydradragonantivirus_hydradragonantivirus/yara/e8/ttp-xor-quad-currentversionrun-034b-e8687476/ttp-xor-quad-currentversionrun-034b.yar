rule TTP_XOR_QUAD_CurrentVersionRun_034b {
  strings:
    $key_034b = { 50 24 [2] 74 2a [2] 5f 06 [2] 71 24 [2] 65 3f [2] 6a 25 [2] 74 38 [2] 76 39 [2] 6d 3f [2] 71 38 [2] 6d 17 }

  condition:
    any of them
}