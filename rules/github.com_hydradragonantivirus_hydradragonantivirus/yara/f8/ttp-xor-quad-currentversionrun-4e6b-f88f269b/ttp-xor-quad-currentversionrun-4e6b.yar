rule TTP_XOR_QUAD_CurrentVersionRun_4e6b {
  strings:
    $key_4e6b = { 1d 04 [2] 39 0a [2] 12 26 [2] 3c 04 [2] 28 1f [2] 27 05 [2] 39 18 [2] 3b 19 [2] 20 1f [2] 3c 18 [2] 20 37 }

  condition:
    any of them
}