rule TTP_XOR_QUAD_CurrentVersionRun_6a4b {
  strings:
    $key_6a4b = { 39 24 [2] 1d 2a [2] 36 06 [2] 18 24 [2] 0c 3f [2] 03 25 [2] 1d 38 [2] 1f 39 [2] 04 3f [2] 18 38 [2] 04 17 }

  condition:
    any of them
}