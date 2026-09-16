rule TTP_XOR_QUAD_CurrentVersionRun_2054 {
  strings:
    $key_2054 = { 73 3b [2] 57 35 [2] 7c 19 [2] 52 3b [2] 46 20 [2] 49 3a [2] 57 27 [2] 55 26 [2] 4e 20 [2] 52 27 [2] 4e 08 }

  condition:
    any of them
}