rule TTP_XOR_QUAD_CurrentVersionRun_7709 {
  strings:
    $key_7709 = { 24 66 [2] 00 68 [2] 2b 44 [2] 05 66 [2] 11 7d [2] 1e 67 [2] 00 7a [2] 02 7b [2] 19 7d [2] 05 7a [2] 19 55 }

  condition:
    any of them
}