rule TTP_XOR_QUAD_CurrentVersionRun_2659 {
  strings:
    $key_2659 = { 75 36 [2] 51 38 [2] 7a 14 [2] 54 36 [2] 40 2d [2] 4f 37 [2] 51 2a [2] 53 2b [2] 48 2d [2] 54 2a [2] 48 05 }

  condition:
    any of them
}