rule TTP_XOR_QUAD_CurrentVersionRun_6629 {
  strings:
    $key_6629 = { 35 46 [2] 11 48 [2] 3a 64 [2] 14 46 [2] 00 5d [2] 0f 47 [2] 11 5a [2] 13 5b [2] 08 5d [2] 14 5a [2] 08 75 }

  condition:
    any of them
}