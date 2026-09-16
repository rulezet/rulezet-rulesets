rule TTP_XOR_QUAD_CurrentVersionRun_e855 {
  strings:
    $key_e855 = { bb 3a [2] 9f 34 [2] b4 18 [2] 9a 3a [2] 8e 21 [2] 81 3b [2] 9f 26 [2] 9d 27 [2] 86 21 [2] 9a 26 [2] 86 09 }

  condition:
    any of them
}