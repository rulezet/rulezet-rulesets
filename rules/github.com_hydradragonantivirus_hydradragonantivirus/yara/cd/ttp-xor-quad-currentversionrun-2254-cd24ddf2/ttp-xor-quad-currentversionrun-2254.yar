rule TTP_XOR_QUAD_CurrentVersionRun_2254 {
  strings:
    $key_2254 = { 71 3b [2] 55 35 [2] 7e 19 [2] 50 3b [2] 44 20 [2] 4b 3a [2] 55 27 [2] 57 26 [2] 4c 20 [2] 50 27 [2] 4c 08 }

  condition:
    any of them
}