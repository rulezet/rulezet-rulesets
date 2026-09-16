rule TTP_XOR_QUAD_CurrentVersionRun_1f4b {
  strings:
    $key_1f4b = { 4c 24 [2] 68 2a [2] 43 06 [2] 6d 24 [2] 79 3f [2] 76 25 [2] 68 38 [2] 6a 39 [2] 71 3f [2] 6d 38 [2] 71 17 }

  condition:
    any of them
}