rule TTP_XOR_QUAD_CurrentVersionRun_4c19 {
  strings:
    $key_4c19 = { 1f 76 [2] 3b 78 [2] 10 54 [2] 3e 76 [2] 2a 6d [2] 25 77 [2] 3b 6a [2] 39 6b [2] 22 6d [2] 3e 6a [2] 22 45 }

  condition:
    any of them
}