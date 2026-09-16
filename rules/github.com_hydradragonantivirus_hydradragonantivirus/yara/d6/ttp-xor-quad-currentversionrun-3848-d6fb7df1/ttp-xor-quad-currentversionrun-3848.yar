rule TTP_XOR_QUAD_CurrentVersionRun_3848 {
  strings:
    $key_3848 = { 6b 27 [2] 4f 29 [2] 64 05 [2] 4a 27 [2] 5e 3c [2] 51 26 [2] 4f 3b [2] 4d 3a [2] 56 3c [2] 4a 3b [2] 56 14 }

  condition:
    any of them
}