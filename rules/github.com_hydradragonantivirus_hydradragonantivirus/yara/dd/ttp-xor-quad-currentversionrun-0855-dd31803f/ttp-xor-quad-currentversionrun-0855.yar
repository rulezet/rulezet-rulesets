rule TTP_XOR_QUAD_CurrentVersionRun_0855 {
  strings:
    $key_0855 = { 5b 3a [2] 7f 34 [2] 54 18 [2] 7a 3a [2] 6e 21 [2] 61 3b [2] 7f 26 [2] 7d 27 [2] 66 21 [2] 7a 26 [2] 66 09 }

  condition:
    any of them
}