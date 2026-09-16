rule TTP_XOR_QUAD_CurrentVersionRun_5009 {
  strings:
    $key_5009 = { 03 66 [2] 27 68 [2] 0c 44 [2] 22 66 [2] 36 7d [2] 39 67 [2] 27 7a [2] 25 7b [2] 3e 7d [2] 22 7a [2] 3e 55 }

  condition:
    any of them
}