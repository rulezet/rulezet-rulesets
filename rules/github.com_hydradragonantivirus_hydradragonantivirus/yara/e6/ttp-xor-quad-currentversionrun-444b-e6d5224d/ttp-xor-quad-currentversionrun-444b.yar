rule TTP_XOR_QUAD_CurrentVersionRun_444b {
  strings:
    $key_444b = { 17 24 [2] 33 2a [2] 18 06 [2] 36 24 [2] 22 3f [2] 2d 25 [2] 33 38 [2] 31 39 [2] 2a 3f [2] 36 38 [2] 2a 17 }

  condition:
    any of them
}