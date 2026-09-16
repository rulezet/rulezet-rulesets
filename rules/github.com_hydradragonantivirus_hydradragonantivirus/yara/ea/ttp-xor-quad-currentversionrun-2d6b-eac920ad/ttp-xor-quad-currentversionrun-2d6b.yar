rule TTP_XOR_QUAD_CurrentVersionRun_2d6b {
  strings:
    $key_2d6b = { 7e 04 [2] 5a 0a [2] 71 26 [2] 5f 04 [2] 4b 1f [2] 44 05 [2] 5a 18 [2] 58 19 [2] 43 1f [2] 5f 18 [2] 43 37 }

  condition:
    any of them
}