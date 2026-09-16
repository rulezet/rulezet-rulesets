rule TTP_XOR_QUAD_CurrentVersionRun_2055 {
  strings:
    $key_2055 = { 73 3a [2] 57 34 [2] 7c 18 [2] 52 3a [2] 46 21 [2] 49 3b [2] 57 26 [2] 55 27 [2] 4e 21 [2] 52 26 [2] 4e 09 }

  condition:
    any of them
}