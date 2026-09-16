rule TTP_XOR_QUAD_CurrentVersionRun_0948 {
  strings:
    $key_0948 = { 5a 27 [2] 7e 29 [2] 55 05 [2] 7b 27 [2] 6f 3c [2] 60 26 [2] 7e 3b [2] 7c 3a [2] 67 3c [2] 7b 3b [2] 67 14 }

  condition:
    any of them
}