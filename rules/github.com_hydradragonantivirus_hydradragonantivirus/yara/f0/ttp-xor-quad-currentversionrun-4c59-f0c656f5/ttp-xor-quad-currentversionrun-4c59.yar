rule TTP_XOR_QUAD_CurrentVersionRun_4c59 {
  strings:
    $key_4c59 = { 1f 36 [2] 3b 38 [2] 10 14 [2] 3e 36 [2] 2a 2d [2] 25 37 [2] 3b 2a [2] 39 2b [2] 22 2d [2] 3e 2a [2] 22 05 }

  condition:
    any of them
}