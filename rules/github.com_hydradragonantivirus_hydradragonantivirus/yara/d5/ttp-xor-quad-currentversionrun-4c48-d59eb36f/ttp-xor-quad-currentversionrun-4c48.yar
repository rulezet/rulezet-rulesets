rule TTP_XOR_QUAD_CurrentVersionRun_4c48 {
  strings:
    $key_4c48 = { 1f 27 [2] 3b 29 [2] 10 05 [2] 3e 27 [2] 2a 3c [2] 25 26 [2] 3b 3b [2] 39 3a [2] 22 3c [2] 3e 3b [2] 22 14 }

  condition:
    any of them
}