rule TTP_XOR_QUAD_CurrentVersionRun_5859 {
  strings:
    $key_5859 = { 0b 36 [2] 2f 38 [2] 04 14 [2] 2a 36 [2] 3e 2d [2] 31 37 [2] 2f 2a [2] 2d 2b [2] 36 2d [2] 2a 2a [2] 36 05 }

  condition:
    any of them
}