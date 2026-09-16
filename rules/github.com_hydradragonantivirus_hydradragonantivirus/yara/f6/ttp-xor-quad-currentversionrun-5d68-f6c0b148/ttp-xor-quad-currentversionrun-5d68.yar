rule TTP_XOR_QUAD_CurrentVersionRun_5d68 {
  strings:
    $key_5d68 = { 0e 07 [2] 2a 09 [2] 01 25 [2] 2f 07 [2] 3b 1c [2] 34 06 [2] 2a 1b [2] 28 1a [2] 33 1c [2] 2f 1b [2] 33 34 }

  condition:
    any of them
}