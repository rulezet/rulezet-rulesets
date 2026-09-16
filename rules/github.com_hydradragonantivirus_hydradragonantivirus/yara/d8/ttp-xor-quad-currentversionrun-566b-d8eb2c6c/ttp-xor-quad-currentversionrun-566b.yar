rule TTP_XOR_QUAD_CurrentVersionRun_566b {
  strings:
    $key_566b = { 05 04 [2] 21 0a [2] 0a 26 [2] 24 04 [2] 30 1f [2] 3f 05 [2] 21 18 [2] 23 19 [2] 38 1f [2] 24 18 [2] 38 37 }

  condition:
    any of them
}