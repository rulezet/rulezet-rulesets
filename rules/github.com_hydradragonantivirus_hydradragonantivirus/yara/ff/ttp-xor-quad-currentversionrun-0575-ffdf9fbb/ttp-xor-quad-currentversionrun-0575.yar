rule TTP_XOR_QUAD_CurrentVersionRun_0575 {
  strings:
    $key_0575 = { 56 1a [2] 72 14 [2] 59 38 [2] 77 1a [2] 63 01 [2] 6c 1b [2] 72 06 [2] 70 07 [2] 6b 01 [2] 77 06 [2] 6b 29 }

  condition:
    any of them
}