rule TTP_XOR_QUAD_CurrentVersionRun_4c55 {
  strings:
    $key_4c55 = { 1f 3a [2] 3b 34 [2] 10 18 [2] 3e 3a [2] 2a 21 [2] 25 3b [2] 3b 26 [2] 39 27 [2] 22 21 [2] 3e 26 [2] 22 09 }

  condition:
    any of them
}