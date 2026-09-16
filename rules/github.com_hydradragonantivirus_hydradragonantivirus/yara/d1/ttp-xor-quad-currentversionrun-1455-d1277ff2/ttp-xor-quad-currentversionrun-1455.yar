rule TTP_XOR_QUAD_CurrentVersionRun_1455 {
  strings:
    $key_1455 = { 47 3a [2] 63 34 [2] 48 18 [2] 66 3a [2] 72 21 [2] 7d 3b [2] 63 26 [2] 61 27 [2] 7a 21 [2] 66 26 [2] 7a 09 }

  condition:
    any of them
}