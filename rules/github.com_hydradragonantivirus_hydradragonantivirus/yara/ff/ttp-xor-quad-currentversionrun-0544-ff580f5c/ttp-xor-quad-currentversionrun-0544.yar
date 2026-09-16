rule TTP_XOR_QUAD_CurrentVersionRun_0544 {
  strings:
    $key_0544 = { 56 2b [2] 72 25 [2] 59 09 [2] 77 2b [2] 63 30 [2] 6c 2a [2] 72 37 [2] 70 36 [2] 6b 30 [2] 77 37 [2] 6b 18 }

  condition:
    any of them
}