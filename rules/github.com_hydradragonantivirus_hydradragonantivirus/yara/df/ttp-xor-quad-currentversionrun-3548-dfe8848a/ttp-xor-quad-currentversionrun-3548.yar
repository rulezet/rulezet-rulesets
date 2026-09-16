rule TTP_XOR_QUAD_CurrentVersionRun_3548 {
  strings:
    $key_3548 = { 66 27 [2] 42 29 [2] 69 05 [2] 47 27 [2] 53 3c [2] 5c 26 [2] 42 3b [2] 40 3a [2] 5b 3c [2] 47 3b [2] 5b 14 }

  condition:
    any of them
}