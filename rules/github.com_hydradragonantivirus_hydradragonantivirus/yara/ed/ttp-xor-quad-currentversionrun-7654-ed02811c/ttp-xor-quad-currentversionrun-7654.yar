rule TTP_XOR_QUAD_CurrentVersionRun_7654 {
  strings:
    $key_7654 = { 25 3b [2] 01 35 [2] 2a 19 [2] 04 3b [2] 10 20 [2] 1f 3a [2] 01 27 [2] 03 26 [2] 18 20 [2] 04 27 [2] 18 08 }

  condition:
    any of them
}