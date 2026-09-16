rule TTP_XOR_QUAD_CurrentVersionRun_7b76 {
  strings:
    $key_7b76 = { 28 19 [2] 0c 17 [2] 27 3b [2] 09 19 [2] 1d 02 [2] 12 18 [2] 0c 05 [2] 0e 04 [2] 15 02 [2] 09 05 [2] 15 2a }

  condition:
    any of them
}