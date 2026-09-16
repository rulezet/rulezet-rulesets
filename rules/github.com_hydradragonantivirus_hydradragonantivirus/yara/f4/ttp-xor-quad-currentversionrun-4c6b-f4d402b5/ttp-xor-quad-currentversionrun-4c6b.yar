rule TTP_XOR_QUAD_CurrentVersionRun_4c6b {
  strings:
    $key_4c6b = { 1f 04 [2] 3b 0a [2] 10 26 [2] 3e 04 [2] 2a 1f [2] 25 05 [2] 3b 18 [2] 39 19 [2] 22 1f [2] 3e 18 [2] 22 37 }

  condition:
    any of them
}