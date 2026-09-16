rule TTP_XOR_QUAD_CurrentVersionRun_2845 {
  strings:
    $key_2845 = { 7b 2a [2] 5f 24 [2] 74 08 [2] 5a 2a [2] 4e 31 [2] 41 2b [2] 5f 36 [2] 5d 37 [2] 46 31 [2] 5a 36 [2] 46 19 }

  condition:
    any of them
}