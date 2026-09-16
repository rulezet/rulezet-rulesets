rule TTP_XOR_QUAD_CurrentVersionRun_5054 {
  strings:
    $key_5054 = { 03 3b [2] 27 35 [2] 0c 19 [2] 22 3b [2] 36 20 [2] 39 3a [2] 27 27 [2] 25 26 [2] 3e 20 [2] 22 27 [2] 3e 08 }

  condition:
    any of them
}