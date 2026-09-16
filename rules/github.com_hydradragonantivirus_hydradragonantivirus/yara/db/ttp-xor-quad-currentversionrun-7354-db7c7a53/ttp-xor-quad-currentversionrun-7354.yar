rule TTP_XOR_QUAD_CurrentVersionRun_7354 {
  strings:
    $key_7354 = { 20 3b [2] 04 35 [2] 2f 19 [2] 01 3b [2] 15 20 [2] 1a 3a [2] 04 27 [2] 06 26 [2] 1d 20 [2] 01 27 [2] 1d 08 }

  condition:
    any of them
}