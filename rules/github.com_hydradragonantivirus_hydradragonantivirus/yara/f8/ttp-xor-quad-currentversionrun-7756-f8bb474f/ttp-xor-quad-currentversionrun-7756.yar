rule TTP_XOR_QUAD_CurrentVersionRun_7756 {
  strings:
    $key_7756 = { 24 39 [2] 00 37 [2] 2b 1b [2] 05 39 [2] 11 22 [2] 1e 38 [2] 00 25 [2] 02 24 [2] 19 22 [2] 05 25 [2] 19 0a }

  condition:
    any of them
}