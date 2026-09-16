rule TTP_XOR_QUAD_CurrentVersionRun_1845 {
  strings:
    $key_1845 = { 4b 2a [2] 6f 24 [2] 44 08 [2] 6a 2a [2] 7e 31 [2] 71 2b [2] 6f 36 [2] 6d 37 [2] 76 31 [2] 6a 36 [2] 76 19 }

  condition:
    any of them
}