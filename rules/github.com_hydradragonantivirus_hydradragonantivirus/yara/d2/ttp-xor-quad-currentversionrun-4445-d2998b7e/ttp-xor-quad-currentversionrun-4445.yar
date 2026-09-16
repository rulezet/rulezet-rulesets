rule TTP_XOR_QUAD_CurrentVersionRun_4445 {
  strings:
    $key_4445 = { 17 2a [2] 33 24 [2] 18 08 [2] 36 2a [2] 22 31 [2] 2d 2b [2] 33 36 [2] 31 37 [2] 2a 31 [2] 36 36 [2] 2a 19 }

  condition:
    any of them
}