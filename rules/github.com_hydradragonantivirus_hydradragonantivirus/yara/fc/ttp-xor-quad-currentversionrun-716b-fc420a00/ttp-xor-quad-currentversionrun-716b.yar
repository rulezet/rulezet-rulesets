rule TTP_XOR_QUAD_CurrentVersionRun_716b {
  strings:
    $key_716b = { 22 04 [2] 06 0a [2] 2d 26 [2] 03 04 [2] 17 1f [2] 18 05 [2] 06 18 [2] 04 19 [2] 1f 1f [2] 03 18 [2] 1f 37 }

  condition:
    any of them
}