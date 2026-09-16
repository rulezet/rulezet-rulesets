rule TTP_XOR_QUAD_CurrentVersionRun_5d48 {
  strings:
    $key_5d48 = { 0e 27 [2] 2a 29 [2] 01 05 [2] 2f 27 [2] 3b 3c [2] 34 26 [2] 2a 3b [2] 28 3a [2] 33 3c [2] 2f 3b [2] 33 14 }

  condition:
    any of them
}