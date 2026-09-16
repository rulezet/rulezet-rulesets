rule TTP_XOR_QUAD_CurrentVersionRun_1869 {
  strings:
    $key_1869 = { 4b 06 [2] 6f 08 [2] 44 24 [2] 6a 06 [2] 7e 1d [2] 71 07 [2] 6f 1a [2] 6d 1b [2] 76 1d [2] 6a 1a [2] 76 35 }

  condition:
    any of them
}