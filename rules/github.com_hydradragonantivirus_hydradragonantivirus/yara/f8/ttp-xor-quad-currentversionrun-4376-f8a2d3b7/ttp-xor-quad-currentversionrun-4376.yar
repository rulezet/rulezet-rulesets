rule TTP_XOR_QUAD_CurrentVersionRun_4376 {
  strings:
    $key_4376 = { 10 19 [2] 34 17 [2] 1f 3b [2] 31 19 [2] 25 02 [2] 2a 18 [2] 34 05 [2] 36 04 [2] 2d 02 [2] 31 05 [2] 2d 2a }

  condition:
    any of them
}