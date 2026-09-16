rule TTP_XOR_QUAD_CurrentVersionRun_1444 {
  strings:
    $key_1444 = { 47 2b [2] 63 25 [2] 48 09 [2] 66 2b [2] 72 30 [2] 7d 2a [2] 63 37 [2] 61 36 [2] 7a 30 [2] 66 37 [2] 7a 18 }

  condition:
    any of them
}