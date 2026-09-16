rule TTP_XOR_QUAD_CurrentVersionRun_336b {
  strings:
    $key_336b = { 60 04 [2] 44 0a [2] 6f 26 [2] 41 04 [2] 55 1f [2] 5a 05 [2] 44 18 [2] 46 19 [2] 5d 1f [2] 41 18 [2] 5d 37 }

  condition:
    any of them
}