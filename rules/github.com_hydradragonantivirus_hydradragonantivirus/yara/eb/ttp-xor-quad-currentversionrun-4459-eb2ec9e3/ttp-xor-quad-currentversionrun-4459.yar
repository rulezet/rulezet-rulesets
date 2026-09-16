rule TTP_XOR_QUAD_CurrentVersionRun_4459 {
  strings:
    $key_4459 = { 17 36 [2] 33 38 [2] 18 14 [2] 36 36 [2] 22 2d [2] 2d 37 [2] 33 2a [2] 31 2b [2] 2a 2d [2] 36 2a [2] 2a 05 }

  condition:
    any of them
}