rule TTP_XOR_QUAD_CurrentVersionRun_0559 {
  strings:
    $key_0559 = { 56 36 [2] 72 38 [2] 59 14 [2] 77 36 [2] 63 2d [2] 6c 37 [2] 72 2a [2] 70 2b [2] 6b 2d [2] 77 2a [2] 6b 05 }

  condition:
    any of them
}