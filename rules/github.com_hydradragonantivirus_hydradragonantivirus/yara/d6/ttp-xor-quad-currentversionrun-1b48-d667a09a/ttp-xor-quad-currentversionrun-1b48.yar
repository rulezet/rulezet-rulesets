rule TTP_XOR_QUAD_CurrentVersionRun_1b48 {
  strings:
    $key_1b48 = { 48 27 [2] 6c 29 [2] 47 05 [2] 69 27 [2] 7d 3c [2] 72 26 [2] 6c 3b [2] 6e 3a [2] 75 3c [2] 69 3b [2] 75 14 }

  condition:
    any of them
}