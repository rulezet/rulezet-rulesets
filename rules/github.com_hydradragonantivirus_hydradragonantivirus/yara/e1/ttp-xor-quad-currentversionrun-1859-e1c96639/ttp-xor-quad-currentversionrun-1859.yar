rule TTP_XOR_QUAD_CurrentVersionRun_1859 {
  strings:
    $key_1859 = { 4b 36 [2] 6f 38 [2] 44 14 [2] 6a 36 [2] 7e 2d [2] 71 37 [2] 6f 2a [2] 6d 2b [2] 76 2d [2] 6a 2a [2] 76 05 }

  condition:
    any of them
}