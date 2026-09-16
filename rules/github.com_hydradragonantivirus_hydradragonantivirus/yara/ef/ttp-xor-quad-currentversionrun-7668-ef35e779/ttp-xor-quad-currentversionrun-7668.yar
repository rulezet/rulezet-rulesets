rule TTP_XOR_QUAD_CurrentVersionRun_7668 {
  strings:
    $key_7668 = { 25 07 [2] 01 09 [2] 2a 25 [2] 04 07 [2] 10 1c [2] 1f 06 [2] 01 1b [2] 03 1a [2] 18 1c [2] 04 1b [2] 18 34 }

  condition:
    any of them
}