rule TTP_XOR_QUAD_CurrentVersionRun_5d35 {
  strings:
    $key_5d35 = { 0e 5a [2] 2a 54 [2] 01 78 [2] 2f 5a [2] 3b 41 [2] 34 5b [2] 2a 46 [2] 28 47 [2] 33 41 [2] 2f 46 [2] 33 69 }

  condition:
    any of them
}