rule TTP_XOR_QUAD_CurrentVersionRun_5a28 {
  strings:
    $key_5a28 = { 09 47 [2] 2d 49 [2] 06 65 [2] 28 47 [2] 3c 5c [2] 33 46 [2] 2d 5b [2] 2f 5a [2] 34 5c [2] 28 5b [2] 34 74 }

  condition:
    any of them
}