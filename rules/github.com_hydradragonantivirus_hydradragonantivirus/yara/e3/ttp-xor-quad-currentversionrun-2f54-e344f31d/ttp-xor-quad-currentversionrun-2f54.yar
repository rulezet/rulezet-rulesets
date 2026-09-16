rule TTP_XOR_QUAD_CurrentVersionRun_2f54 {
  strings:
    $key_2f54 = { 7c 3b [2] 58 35 [2] 73 19 [2] 5d 3b [2] 49 20 [2] 46 3a [2] 58 27 [2] 5a 26 [2] 41 20 [2] 5d 27 [2] 41 08 }

  condition:
    any of them
}