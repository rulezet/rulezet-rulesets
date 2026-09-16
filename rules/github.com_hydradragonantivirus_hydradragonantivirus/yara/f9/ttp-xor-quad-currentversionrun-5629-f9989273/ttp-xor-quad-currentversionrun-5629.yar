rule TTP_XOR_QUAD_CurrentVersionRun_5629 {
  strings:
    $key_5629 = { 05 46 [2] 21 48 [2] 0a 64 [2] 24 46 [2] 30 5d [2] 3f 47 [2] 21 5a [2] 23 5b [2] 38 5d [2] 24 5a [2] 38 75 }

  condition:
    any of them
}