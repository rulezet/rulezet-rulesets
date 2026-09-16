rule TTP_XOR_QUAD_CurrentVersionRun_736b {
  strings:
    $key_736b = { 20 04 [2] 04 0a [2] 2f 26 [2] 01 04 [2] 15 1f [2] 1a 05 [2] 04 18 [2] 06 19 [2] 1d 1f [2] 01 18 [2] 1d 37 }

  condition:
    any of them
}