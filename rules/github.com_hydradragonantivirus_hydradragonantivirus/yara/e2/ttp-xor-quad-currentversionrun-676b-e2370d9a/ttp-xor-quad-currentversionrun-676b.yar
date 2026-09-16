rule TTP_XOR_QUAD_CurrentVersionRun_676b {
  strings:
    $key_676b = { 34 04 [2] 10 0a [2] 3b 26 [2] 15 04 [2] 01 1f [2] 0e 05 [2] 10 18 [2] 12 19 [2] 09 1f [2] 15 18 [2] 09 37 }

  condition:
    any of them
}