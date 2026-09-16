rule TTP_XOR_QUAD_CurrentVersionRun_7205 {
  strings:
    $key_7205 = { 21 6a [2] 05 64 [2] 2e 48 [2] 00 6a [2] 14 71 [2] 1b 6b [2] 05 76 [2] 07 77 [2] 1c 71 [2] 00 76 [2] 1c 59 }

  condition:
    any of them
}