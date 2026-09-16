rule TTP_XOR_QUAD_CurrentVersionRun_5d09 {
  strings:
    $key_5d09 = { 0e 66 [2] 2a 68 [2] 01 44 [2] 2f 66 [2] 3b 7d [2] 34 67 [2] 2a 7a [2] 28 7b [2] 33 7d [2] 2f 7a [2] 33 55 }

  condition:
    any of them
}