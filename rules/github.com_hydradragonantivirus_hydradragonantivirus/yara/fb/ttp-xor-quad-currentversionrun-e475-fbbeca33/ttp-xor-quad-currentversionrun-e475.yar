rule TTP_XOR_QUAD_CurrentVersionRun_e475 {
  strings:
    $key_e475 = { b7 1a [2] 93 14 [2] b8 38 [2] 96 1a [2] 82 01 [2] 8d 1b [2] 93 06 [2] 91 07 [2] 8a 01 [2] 96 06 [2] 8a 29 }

  condition:
    any of them
}