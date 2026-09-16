rule TTP_XOR_QUAD_CurrentVersionRun_3145 {
  strings:
    $key_3145 = { 62 2a [2] 46 24 [2] 6d 08 [2] 43 2a [2] 57 31 [2] 58 2b [2] 46 36 [2] 44 37 [2] 5f 31 [2] 43 36 [2] 5f 19 }

  condition:
    any of them
}