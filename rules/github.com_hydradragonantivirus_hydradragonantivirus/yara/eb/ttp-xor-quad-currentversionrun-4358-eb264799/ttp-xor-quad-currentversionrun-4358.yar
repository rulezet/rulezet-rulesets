rule TTP_XOR_QUAD_CurrentVersionRun_4358 {
  strings:
    $key_4358 = { 10 37 [2] 34 39 [2] 1f 15 [2] 31 37 [2] 25 2c [2] 2a 36 [2] 34 2b [2] 36 2a [2] 2d 2c [2] 31 2b [2] 2d 04 }

  condition:
    any of them
}