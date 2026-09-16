rule TTP_XOR_QUAD_CurrentVersionRun_2f4b {
  strings:
    $key_2f4b = { 7c 24 [2] 58 2a [2] 73 06 [2] 5d 24 [2] 49 3f [2] 46 25 [2] 58 38 [2] 5a 39 [2] 41 3f [2] 5d 38 [2] 41 17 }

  condition:
    any of them
}