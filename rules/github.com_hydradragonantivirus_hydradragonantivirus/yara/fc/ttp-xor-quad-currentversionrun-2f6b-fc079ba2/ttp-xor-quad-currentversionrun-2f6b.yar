rule TTP_XOR_QUAD_CurrentVersionRun_2f6b {
  strings:
    $key_2f6b = { 7c 04 [2] 58 0a [2] 73 26 [2] 5d 04 [2] 49 1f [2] 46 05 [2] 58 18 [2] 5a 19 [2] 41 1f [2] 5d 18 [2] 41 37 }

  condition:
    any of them
}